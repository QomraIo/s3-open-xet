//! The Postgres index against the backend conformance suite: every case of
//! `openxet_index::conformance`, each in a database of its own created on
//! the service `OPENXET_TEST_POSTGRES_URL` names, with a second pool on the
//! same database as the second node. Without the variable the cases are
//! skipped, and under `OPENXET_REQUIRE_SERVICES=1` they fail instead.

use openxet_index::conformance::Fixture;
use openxet_index::{PgConnectOptions, PostgresIndex};
use sqlx::Connection as _;

const URL_VAR: &str = "OPENXET_TEST_POSTGRES_URL";

/// Enough for a case's two pools and its concurrent writers, well under a
/// test service's connection limit when cases run in parallel.
const MAX_CONNECTIONS: u32 = 8;

struct Postgres {
    /// The service, from `OPENXET_TEST_POSTGRES_URL`; `None` skips.
    service: Option<PgConnectOptions>,
}

fn postgres() -> Postgres {
    let service = std::env::var(URL_VAR).ok().map(|url| match url.parse() {
        Ok(options) => options,
        Err(e) => panic!("{URL_VAR} is not a Postgres URL: {e}"),
    });
    assert!(
        service.is_some() || std::env::var("OPENXET_REQUIRE_SERVICES").as_deref() != Ok("1"),
        "OPENXET_REQUIRE_SERVICES=1, but {URL_VAR} is unset"
    );
    Postgres { service }
}

async fn connect(options: PgConnectOptions) -> PostgresIndex {
    match PostgresIndex::connect(options, MAX_CONNECTIONS).await {
        Ok(index) => index,
        Err(e) => panic!("connect to the test database: {e}"),
    }
}

#[async_trait::async_trait]
impl Fixture for Postgres {
    type Index = PostgresIndex;

    async fn fresh(&self) -> PostgresIndex {
        let Some(service) = &self.service else {
            panic!("{URL_VAR} is unset; skip_reason should have skipped this case");
        };
        let name = format!("openxet_test_{}", uuid::Uuid::now_v7().simple());
        let mut admin = match sqlx::PgConnection::connect_with(service).await {
            Ok(conn) => conn,
            Err(e) => panic!("connect to {URL_VAR}: {e}"),
        };
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
        {
            panic!("create the test database {name}: {e}");
        }
        drop(admin.close().await);
        connect(service.clone().database(&name)).await
    }

    async fn second_handle(&self, of: &PostgresIndex) -> PostgresIndex {
        connect(of.connect_options()).await
    }

    fn skip_reason(&self) -> Option<String> {
        self.service
            .is_none()
            .then(|| format!("{URL_VAR} is unset, so there is no Postgres to test against"))
    }
}

openxet_index::index_conformance!(postgres: cas, repos, git);
