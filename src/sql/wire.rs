//! SQL API v2 wire types (private): only the fields the client reads.

use serde::Deserialize;

pub(crate) type Rows = Vec<Vec<Option<String>>>;

/// Body of a 200/202/4xx answer to `POST /api/v2/statements` or `GET …/{handle}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StatementResponse {
    pub statement_handle: Option<String>,
    /// The children of a multi-statement request, in order (ADR 0004, A2).
    pub statement_handles: Option<Vec<String>>,
    pub code: Option<String>,
    pub sql_state: Option<String>,
    pub message: Option<String>,
    pub result_set_meta_data: Option<ResultSetMetaData>,
    pub data: Option<Rows>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResultSetMetaData {
    /// One entry per partition; their content is not needed.
    #[serde(default)]
    pub partition_info: Vec<serde::de::IgnoredAny>,
    pub row_type: Vec<RowType>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RowType {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub precision: Option<i64>,
    pub scale: Option<i64>,
    #[serde(default)]
    pub nullable: bool,
}

/// Body of `GET …/{handle}?partition=N`.
#[derive(Debug, Deserialize)]
pub(super) struct PartitionResponse {
    pub data: Rows,
}
