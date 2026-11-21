//! Azure: a managed identity's Entra ID access token for Snowflake's resource (the connector's
//! `create_azure_attestation`): AKS workload identity, Azure Functions, or IMDS.

use super::{Attester, Reply, WIF_CREDENTIALS_NOT_FOUND, WifError, jwt, status_text};
use crate::codec::percent_encode;
use crate::secret::Secret;

/// The connector's `DEFAULT_ENTRA_SNOWFLAKE_RESOURCE`.
const SNOWFLAKE_RESOURCE: &str = "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad";

impl Attester<'_> {
    pub(super) fn azure_attestation(&self) -> Result<Secret, WifError> {
        let token = match self.aks_settings() {
            Some((client_id, tenant_id, token_file)) => {
                self.aks_token(&client_id, &tenant_id, &token_file)?
            }
            None => self.managed_identity_token()?,
        };
        jwt::issuer_and_subject(token.expose())?;
        Ok(token)
    }

    /// The AKS workload identity webhook's variables, when its token file exists.
    fn aks_settings(&self) -> Option<(String, String, String)> {
        let client_id = self.env.get_non_empty("AZURE_CLIENT_ID")?;
        let tenant_id = self.env.get_non_empty("AZURE_TENANT_ID")?;
        let token_file = self.env.get_non_empty("AZURE_FEDERATED_TOKEN_FILE")?;
        std::path::Path::new(token_file).exists().then(|| {
            (
                client_id.to_string(),
                tenant_id.to_string(),
                token_file.to_string(),
            )
        })
    }

    /// azure-identity's `WorkloadIdentityCredential`: the federated token file exchanged for an
    /// access token (client credentials with a JWT assertion).
    fn aks_token(
        &self,
        client_id: &str,
        tenant_id: &str,
        token_file: &str,
    ) -> Result<Secret, WifError> {
        let failed = |why: String| {
            WifError::new(
                WIF_CREDENTIALS_NOT_FOUND,
                format!(
                    "Error fetching Azure MI token via WorkloadIdentityCredential: {why}. Ensure the application is running on AKS with workload identity configured."
                ),
            )
        };
        let assertion = std::fs::read_to_string(token_file)
            .map(|t| Secret::new(t.trim()))
            .map_err(|e| failed(format!("cannot read {token_file}: {e}")))?;
        let authority = self
            .env
            .get_non_empty("AZURE_AUTHORITY_HOST")
            .unwrap_or(&self.endpoints.azure_authority);
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            authority.trim_end_matches('/'),
            percent_encode(tenant_id, b"")
        );
        let body = Secret::new(format!(
            "client_assertion={}&client_assertion_type={}&client_id={}&grant_type=client_credentials&scope={}",
            percent_encode(assertion.expose(), b""),
            percent_encode(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                b""
            ),
            percent_encode(client_id, b""),
            percent_encode(&format!("{SNOWFLAKE_RESOURCE}/.default"), b"")
        ));
        let reply = self
            .send(
                &self.remote,
                "POST",
                &url,
                &[("Content-Type", "application/x-www-form-urlencoded")],
                body.expose(),
            )
            .map_err(failed)?;
        access_token(&reply).map_err(failed)
    }

    /// IMDS, or the Azure Functions identity endpoint when `IDENTITY_ENDPOINT` is set.
    fn managed_identity_token(&self) -> Result<Secret, WifError> {
        let identity_header;
        let (base, mut query, headers): (&str, String, Vec<(&str, &str)>) =
            match self.env.get("IDENTITY_ENDPOINT") {
                Some(endpoint) => {
                    identity_header = self.env.get("IDENTITY_HEADER").ok_or_else(|| {
                        WifError::new(
                            WIF_CREDENTIALS_NOT_FOUND,
                            "Managed identity is not enabled on this Azure function.",
                        )
                    })?;
                    (
                        endpoint,
                        format!("api-version=2019-08-01&resource={SNOWFLAKE_RESOURCE}"),
                        vec![("X-IDENTITY-HEADER", identity_header)],
                    )
                }
                None => (
                    self.endpoints.azure_imds_token.as_str(),
                    format!("api-version=2018-02-01&resource={SNOWFLAKE_RESOURCE}"),
                    vec![("Metadata", "true")],
                ),
            };
        if let Some(client_id) = self.env.get_non_empty("MANAGED_IDENTITY_CLIENT_ID") {
            query.push_str(&format!("&client_id={}", percent_encode(client_id, b"")));
        }
        let failed = |why: String| {
            WifError::new(
                WIF_CREDENTIALS_NOT_FOUND,
                format!(
                    "Error fetching Azure metadata: {why}. Ensure the application is running on Azure."
                ),
            )
        };
        let reply = self
            .get(&self.local, &format!("{base}?{query}"), &headers)
            .map_err(failed)?;
        access_token(&reply).map_err(|why| {
            if why.starts_with("HTTP") {
                failed(why)
            } else {
                WifError::new(
                    WIF_CREDENTIALS_NOT_FOUND,
                    "No access token found in Azure metadata service response.",
                )
            }
        })
    }
}

/// `access_token` of a 200 JSON reply; `Err` names the status or the missing field only.
fn access_token(reply: &Reply) -> Result<Secret, String> {
    if reply.status != 200 {
        return Err(status_text(reply));
    }
    serde_json::from_str::<serde_json::Value>(&reply.body)
        .ok()
        .and_then(|v| v.get("access_token")?.as_str().map(Secret::new))
        .filter(|t| !t.expose().is_empty())
        .ok_or_else(|| "no access_token in the response".to_string())
}
