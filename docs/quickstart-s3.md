# Quickstart: storage on S3

<!-- description: Keep an OpenXet server's data in an Amazon S3 bucket: enter your AWS credentials once, create a bucket or use one you have, then upload and download with the stock hf CLI. -->

Keep everything an OpenXet server stores in an Amazon S3 bucket instead of
on its disk. You enter your AWS credentials once, choose a new bucket or
one you already have, and start the server. Then you upload a folder with
Hugging Face's stock `hf` command line, download it again and look at
what landed in the bucket.

Run the blocks in one terminal, in an empty directory. Unlike the [Hub quickstart](quickstart-hub.md), this page
doesn't run in CI, since it needs your AWS account.

## 1. Install

There is no release yet, so `openxet` is built from source. This needs
[Rust](https://rustup.rs) 1.97 or newer, Python 3.10 or newer and `git`
2.37 or newer. The `hf` command line goes into a virtual environment:

```bash install
cargo install --locked --git https://github.com/stubbi/openxet openxet
python3 -m venv .venv && . .venv/bin/activate
pip install 'huggingface_hub>=2.2.0' 'hf_xet>=1.7.0'
```

## 2. Get AWS credentials

OpenXet signs in to S3 with an access key: an access key ID and its
secret access key. Create one for an IAM user in the
[IAM console](https://console.aws.amazon.com/iam/) (Users, your user,
Security credentials, Create access key). Give the user this policy,
with your bucket's name in place of `my-openxet-bucket`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:CreateBucket"],
      "Resource": "arn:aws:s3:::my-openxet-bucket"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::my-openxet-bucket/*"
    }
  ]
}
```

`s3:CreateBucket` is only needed if OpenXet should create the bucket
for you; leave it out for a bucket you already have.

## 3. Connect OpenXet to S3

Choose the bucket and its region. Bucket names are shared by every AWS
account, so pick one that is yours: lowercase letters, digits and hyphens,
3 to 63 characters. OpenXet keeps its data under a prefix, here `openxet`,
so the bucket can hold other things too.

```bash
BUCKET=my-openxet-bucket
REGION=eu-west-1
```

Then run `openxet storage setup`, the one step that connects a server to
S3. Pick one of the two commands.

**A new bucket.** `--create-bucket` creates it in `$REGION`:

```bash
openxet storage setup "s3://$BUCKET/openxet" --region "$REGION" --create-bucket
```

**A bucket you already have.** Leave `--create-bucket` out and give the
bucket's own region:

```bash
openxet storage setup "s3://$BUCKET/openxet" --region "$REGION"
```

It asks for your access key. The secret isn't shown as you type it:

```text
Access key id: AKIAIOSFODNN7EXAMPLE
Secret access key:
Created the bucket of s3://my-openxet-bucket/openxet.
The store honours conditional creates.
The credentials are in /home/me/.config/openxet/s3-credentials (mode 0600), the transfer key in /home/me/.config/openxet/transfer.key.
Wrote the configuration to /home/me/.config/openxet/openxet.toml.

Start the server with:
  openxet serve --config /home/me/.config/openxet/openxet.toml
```

For a bucket you already have, the first line reads
`The bucket of s3://my-openxet-bucket/openxet exists.` instead.

Before it writes anything, `storage setup` checks that the access key
reaches the bucket. It also checks that S3 refuses to overwrite an object
that a request said must be new, which OpenXet relies on to keep two
uploads of the same file from colliding. Only then does it store the
access key in a file that only you can read, and write a configuration
that names that file. The configuration itself never holds the key:

```toml
# Written by `openxet storage setup`. The credentials are in storage.credentials_file,
# never in this file.

[cas]
transfer_key_file = "/home/me/.config/openxet/transfer.key"

[storage]
url = "s3://my-openxet-bucket/openxet"
credentials_file = "/home/me/.config/openxet/s3-credentials"

[storage.options]
region = "eu-west-1"
```

Setting up a server, or a CI job, that has no terminal to type on? Put
the key in `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` first, and
`storage setup` takes it from there without asking. Add `--dry-run` to
check the key and the bucket without creating or writing anything.

## 4. Start the server

```bash
openxet serve --config ~/.config/openxet/openxet.toml --port 0 --json > serve.json 2> serve.log &
SERVER=$!
until [ -s serve.json ]; do sleep 0.1; done
```

Before it takes any request, the server checks the bucket again with the
stored key. The configuration has no `[auth]` section, so the server runs
in [dev mode](reference/config.md#dev-mode), with one token that may do
everything. `--port 0` picks a free port, and `--json` prints the
endpoint and the token on one line once the server is ready.

## 5. Upload and download with `hf`

Point `hf` at the server, make a folder with a README and a 4 MiB file,
and upload it to the repository `dev/demo`:

```bash
export HF_ENDPOINT=$(python3 -c 'import json; print(json.load(open("serve.json"))["endpoint"])')
export HF_TOKEN=$(python3 -c 'import json; print(json.load(open("serve.json"))["token"])')
mkdir demo
echo "# demo" > demo/README.md
head -c 4194304 /dev/urandom > demo/data.bin
hf upload dev/demo demo .
```

```text
Found 2 files to upload
✓ Uploaded
  url: http://127.0.0.1:56398/dev/demo/commit/48995c751d05a7c3ccb8ea13b2b49a4b9a9e9507
```

Download it again and compare:

```bash
hf download dev/demo --local-dir downloaded
cmp demo/data.bin downloaded/data.bin
```

`cmp` prints nothing: the files are identical, and the bytes came back
from S3.

## 6. Look in the bucket

Open the bucket in the [S3 console](https://console.aws.amazon.com/s3/),
or list it with the [AWS CLI](https://aws.amazon.com/cli/):

```bash
aws s3 ls "s3://$BUCKET/openxet/" --recursive
```

Under `openxet/` are the file's chunks (`xorbs/`), what the upload
registered (`shards/`, `registrations/`, `xorb-owners/`), the repository's
Git history (`repos/`), and one small object for each conditional-create
check that `storage setup` and every server start made (`probe/`). The keys
are laid out as a local OpenXet bucket lays out its files, so you can copy
a local bucket into S3 with `aws s3 sync` and the server reads it as it
is ([storage](reference/config.md#storage)).

## 7. Stop the server

```bash
kill "$SERVER"
```

The next `openxet serve --config ~/.config/openxet/openxet.toml` serves
the same repository again. Run it from the same directory: the server
keeps its index in `openxet-data` there, while every file stays in S3.

When you are done trying, delete the `openxet/` prefix or the bucket in
the S3 console, so it stops costing storage.

## If something goes wrong

`storage setup` stops at the first problem and writes nothing; fix it
and run the same command again.

| Message | What to do |
| ------- | ---------- |
| `the bucket of s3://… does not exist` | Check the name, or add `--create-bucket` to create it. |
| `access denied: the credentials may not use this bucket, or another account owns it` | Check the access key and the IAM policy from step 2. For a new bucket, the name may belong to someone else: pick another. |
| `the bucket is in another region than …` | Pass the bucket's own region with `--region`. |
| `another account owns a bucket of this name` | Bucket names are global: pick another. |
| `no credentials for the object store` | Run it in a terminal to be asked for the key, or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. |
| `… already sets storage.url` | That configuration is already connected. Remove its `[storage]` section to set it up again, or pass another `--config`. |

Every error, with `--json` too, is listed in
[exit codes](reference/exit-codes.md).

## Next

- [`openxet storage setup`](reference/cli.md#openxet-storage-setup): every
  option, including `--endpoint` for S3-compatible stores such as
  Cloudflare R2.
- [Storage settings](reference/config.md#storage): the `[storage]` section
  `storage setup` writes, and the permissions the access key needs.
- [Server configuration](reference/config.md): real users with
  [static tokens](reference/config.md#static-tokens) in place of dev mode.
- [Quickstart: hf and git](quickstart-hub.md): clone and push the same
  repository with `git`.
