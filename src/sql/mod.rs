//! SQL REST API v2 client and the typed result model (ADR 0001, Decisions 1, 5 and 6; ADR 0002).

pub mod client;
mod convert;
pub mod executor;
mod prefetch;
pub mod result;
pub mod script;
pub mod stream;
mod wire;

pub(crate) use client::DEFAULT_PARTITION_CONCURRENCY;
pub use client::{ClientOptions, PARTITION_CONCURRENCY_VAR, SqlClient};
pub use executor::{Executor, RunNeeds};
pub use result::{Column, QueryResult, SfType, Value};
pub use script::{ScriptOptions, ScriptRun};
pub use stream::RowStream;
