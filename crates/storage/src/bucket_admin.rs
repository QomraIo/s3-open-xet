//! The S3 bucket itself, for `openxet storage setup`: whether it exists, and
//! creating it. `object_store` reads and writes objects but has no call for
//! the bucket, so these are two `SigV4`-signed requests made with its own
//! signer, credential provider and HTTP client:
//! [`HeadBucket`](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html)
//! and [`CreateBucket`](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html).

use bytes::Bytes;
use object_store::ClientConfigKey;
use object_store::aws::{AmazonS3, AmazonS3Builder, AmazonS3ConfigKey, AwsAuthorizer};
use object_store::client::{
    ClientOptions, HttpClient, HttpConnector as _, HttpRequest, HttpRequestBody, ReqwestConnector,
};

use crate::StorageError;

/// Where the bucket's own requests go, and how they are signed.
#[derive(Debug)]
pub(crate) struct BucketAdmin {
    /// The bucket's URL: `https://s3.{region}.amazonaws.com/{bucket}`, or
    /// the endpoint's equivalent, as `object_store` addresses it.
    bucket_url: String,
    region: String,
    store: AmazonS3,
    client: HttpClient,
}

/// What [`ObjectBucket::create_bucket`](crate::ObjectBucket::create_bucket) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketCreated {
    /// This call created the bucket.
    Created,
    /// The bucket already existed, owned by these credentials' account.
    AlreadyOwned,
}

impl BucketAdmin {
    /// The admin for the bucket `builder` was configured with, signing with
    /// `store`'s credentials (from the options, the environment or the
    /// instance) so it reaches the store exactly as the bucket does.
    pub(crate) fn new(
        builder: &AmazonS3Builder,
        store: AmazonS3,
        bucket: &str,
    ) -> Result<Self, String> {
        let config = |key| builder.get_config_value(&key);
        let region = config(AmazonS3ConfigKey::Region).unwrap_or_else(|| "us-east-1".to_owned());
        let virtual_hosted = config(AmazonS3ConfigKey::VirtualHostedStyleRequest)
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        // The same choice `AmazonS3Builder::build` makes; an endpoint for
        // virtual-hosted requests already names the bucket.
        let bucket_url = match (config(AmazonS3ConfigKey::Endpoint), virtual_hosted) {
            (Some(endpoint), true) => endpoint,
            (Some(endpoint), false) => format!("{}/{bucket}", endpoint.trim_end_matches('/')),
            (None, true) => format!("https://{bucket}.s3.{region}.amazonaws.com"),
            (None, false) => format!("https://s3.{region}.amazonaws.com/{bucket}"),
        };
        let allow_http = config(AmazonS3ConfigKey::Client(ClientConfigKey::AllowHttp))
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let client = ReqwestConnector::default()
            .connect(&ClientOptions::new().with_allow_http(allow_http))
            .map_err(|err| err.to_string())?;
        Ok(Self {
            bucket_url,
            region,
            store,
            client,
        })
    }

    /// Whether the bucket exists. `false` only on `404`: a bucket these
    /// credentials may not read is an error, never reported as missing.
    pub(crate) async fn exists(&self) -> Result<bool, StorageError> {
        let (status, body) = self.send(http::Method::HEAD, Bytes::new()).await?;
        match status {
            200..=299 => Ok(true),
            404 => Ok(false),
            _ => Err(self.refused("look up", status, &body)),
        }
    }

    /// Creates the bucket, in the configured region.
    pub(crate) async fn create(&self) -> Result<BucketCreated, StorageError> {
        // us-east-1 is the default location, and refuses being named.
        let body = if self.region == "us-east-1" {
            Bytes::new()
        } else {
            Bytes::from(format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
                self.region
            ))
        };
        let (status, text) = self.send(http::Method::PUT, body).await?;
        match status {
            200..=299 => Ok(BucketCreated::Created),
            409 if text.contains("BucketAlreadyOwnedByYou") => Ok(BucketCreated::AlreadyOwned),
            _ => Err(self.refused("create", status, &text)),
        }
    }

    async fn send(&self, method: http::Method, body: Bytes) -> Result<(u16, String), StorageError> {
        let failed = |op: &'static str, err: Box<dyn std::error::Error + Send + Sync>| {
            StorageError::Remote {
                op,
                location: self.bucket_url.clone(),
                source: err,
            }
        };
        let credential = self
            .store
            .credentials()
            .get_credential()
            .await
            .map_err(|err| failed("get credentials for", Box::new(err)))?;
        let mut request: HttpRequest = http::Request::builder()
            .method(method)
            .uri(&self.bucket_url)
            .body(HttpRequestBody::from(body))
            .map_err(|err| failed("build a request for", Box::new(err)))?;
        AwsAuthorizer::new(&credential, "s3", &self.region).authorize(&mut request, None);
        let response = self
            .client
            .execute(request)
            .await
            .map_err(|err| failed("reach", Box::new(err)))?;
        let status = response.status().as_u16();
        let text = response
            .into_body()
            .bytes()
            .await
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        Ok((status, text))
    }

    /// A refusal from the store, with the S3 error code if it sent one.
    fn refused(&self, op: &'static str, status: u16, body: &str) -> StorageError {
        let code = body
            .split_once("<Code>")
            .and_then(|(_, rest)| rest.split_once("</Code>"))
            .map(|(code, _)| code);
        let why = match (status, code) {
            (301, _) => format!(
                "the bucket is in another region than {}; set [storage.options] region to \
                 its region",
                self.region
            ),
            (403, _) => "access denied: the credentials may not use this bucket, or another \
                         account owns it"
                .to_owned(),
            (409, Some("BucketAlreadyExists")) => {
                "another account owns a bucket of this name; bucket names are global, so \
                 choose another"
                    .to_owned()
            }
            (_, Some(code)) => format!("HTTP {status}, {code}"),
            (_, None) => format!("HTTP {status}"),
        };
        StorageError::Remote {
            op,
            location: self.bucket_url.clone(),
            source: why.into(),
        }
    }
}
