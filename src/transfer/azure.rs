//! Azure Blob stages (connector `azure_storage_client.py`): a SAS token on every URL, block
//! blobs, block lists for large files.

use super::crypto::Metadata;
use super::storage::{
    Body, Credentials, Download, Header, Http, Multipart, Request, RequestBody, Response, Storage,
    Upload, copy_body, http_error, part_size, split_location,
};
use crate::codec::percent_encode;
use crate::error::Result;
use std::io::Write;

const MIB: u64 = 1 << 20;
/// Answers that mean the SAS token expired (`TOKEN_EXPIRATION_ERR_MESSAGE`).
const EXPIRED: [&str; 2] = [
    "Signature not valid in the specified time frame",
    "Server failed to authenticate the request.",
];

pub(crate) struct Azure<'a> {
    http: &'a Http,
    creds: &'a Credentials<'a>,
    /// `https://<account>.blob.<endpoint>/<container>`, or the test override.
    base: String,
    prefix: String,
}

impl<'a> Azure<'a> {
    pub(crate) fn new(
        stage: &serde_json::Value,
        http: &'a Http,
        creds: &'a Credentials<'a>,
        endpoint_override: Option<&str>,
    ) -> Self {
        let end_point = stage["endPoint"].as_str().unwrap_or_default();
        let end_point = end_point.strip_prefix("blob.").unwrap_or(end_point);
        let account = stage["storageAccount"].as_str().unwrap_or_default();
        let (container, prefix) = split_location(stage["location"].as_str().unwrap_or_default());
        let host = match endpoint_override {
            Some(base) => base.trim_end_matches('/').to_string(),
            None => format!("https://{account}.blob.{end_point}"),
        };
        Self {
            http,
            creds,
            base: format!("{host}/{}", percent_encode(&container, b"/")),
            prefix,
        }
    }

    fn url(&self, name: &str) -> String {
        format!(
            "{}/{}",
            self.base,
            percent_encode(
                &format!("{}{}", self.prefix, name.trim_start_matches('/')),
                b"/",
            )
        )
    }

    fn send(
        &self,
        method: &'static str,
        url: &str,
        headers: Vec<(String, String)>,
        body: &RequestBody,
    ) -> Result<Response> {
        let build = || -> Result<(Request, u64)> {
            let (sas, generation) = self.creds.get("AZURE_SAS_TOKEN");
            let sas = sas.map(|s| s.expose().trim_start_matches('?').to_string());
            let target = match sas {
                Some(sas) if url.contains('?') => format!("{url}&{sas}"),
                Some(sas) => format!("{url}?{sas}"),
                None => url.to_string(),
            };
            let body = match body {
                RequestBody::None => RequestBody::None,
                RequestBody::Bytes(b) => RequestBody::Bytes(b.clone()),
                RequestBody::File(f) => RequestBody::File(f.clone()),
            };
            Ok((
                Request {
                    method,
                    url: target,
                    headers: headers.clone(),
                    body,
                },
                generation,
            ))
        };
        let expired =
            |status: u16, text: &str| status == 403 && EXPIRED.iter().any(|m| text.contains(m));
        let response = self.http.send(&build, &expired, &|g| self.creds.renew(g))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) || (method == "HEAD" && status == 404) {
            Ok(response)
        } else {
            Err(http_error(method, url, status))
        }
    }

    fn metadata(upload: &Upload<'_>) -> Vec<(String, String)> {
        let mut meta = vec![("x-ms-meta-sfcdigest".to_string(), upload.digest.to_string())];
        if let Some(enc) = upload.encryption {
            meta.push((
                "x-ms-meta-encryptiondata".into(),
                encryption_data(enc, "AES_CBC_128"),
            ));
            meta.push(("x-ms-meta-matdesc".into(), enc.matdesc.clone()));
        }
        meta
    }
}

/// The `encryptiondata` JSON the connector stores (Azure and GCS), in its key order.
pub(crate) fn encryption_data(enc: &Metadata, content_algorithm: &str) -> String {
    let quote = |s: &str| serde_json::Value::from(s).to_string();
    format!(
        "{{\"EncryptionMode\": \"FullBlob\", \"WrappedContentKey\": {{\"KeyId\": \"symmKey1\", \
         \"EncryptedKey\": {}, \"Algorithm\": \"AES_CBC_256\"}}, \"EncryptionAgent\": \
         {{\"Protocol\": \"1.0\", \"EncryptionAlgorithm\": \"{content_algorithm}\"}}, \
         \"ContentEncryptionIV\": {}, \"KeyWrappingMetadata\": {{\"EncryptionLibrary\": \
         \"Java 5.3.0\"}}}}",
        quote(&enc.key),
        quote(&enc.iv)
    )
}

/// Reads `encryptiondata` + `matdesc` back.
pub(crate) fn parse_encryption_data(data: &str, matdesc: Option<&str>) -> Option<Metadata> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    Some(Metadata {
        key: value["WrappedContentKey"]["EncryptedKey"]
            .as_str()?
            .to_string(),
        iv: value["ContentEncryptionIV"].as_str()?.to_string(),
        matdesc: matdesc.unwrap_or_default().to_string(),
    })
}

fn header(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

impl Storage for Azure<'_> {
    fn chunk_size(&self, size: u64) -> Option<u64> {
        Some(part_size(size, 8 * MIB, 50_000, 8 * MIB))
    }

    fn head(&self, name: &str, _presigned_url: Option<&str>) -> Result<Option<Header>> {
        let response = self.send("HEAD", &self.url(name), Vec::new(), &RequestBody::None)?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let encryption = header(&response, "x-ms-meta-encryptiondata").and_then(|data| {
            parse_encryption_data(&data, header(&response, "x-ms-meta-matdesc").as_deref())
        });
        Ok(Some(Header {
            size: header(&response, "Content-Length").and_then(|v| v.parse().ok()),
            encryption,
        }))
    }

    fn put(&self, upload: &Upload<'_>, body: &Body) -> Result<()> {
        let mut headers = vec![
            ("x-ms-blob-type".to_string(), "BlockBlob".to_string()),
            ("Content-Encoding".to_string(), "utf-8".to_string()),
        ];
        headers.extend(Self::metadata(upload));
        self.send(
            "PUT",
            &self.url(upload.name),
            headers,
            &RequestBody::File(body.clone()),
        )
        .map(drop)
    }

    fn begin_multipart(&self, _upload: &Upload<'_>, parts: usize) -> Result<Multipart> {
        // 20 random hex digits per block, as the connector.
        let mut block_ids = Vec::with_capacity(parts);
        for _ in 0..parts {
            let bytes = super::crypto::random(10)?;
            block_ids.push(bytes.iter().map(|b| format!("{b:02x}")).collect());
        }
        Ok(Multipart {
            upload_id: String::new(),
            block_ids,
        })
    }

    fn put_part(
        &self,
        upload: &Upload<'_>,
        multipart: &Multipart,
        index: usize,
        body: &Body,
    ) -> Result<String> {
        let block = multipart.block_ids.get(index).cloned().unwrap_or_default();
        let url = format!("{}?comp=block&blockid={block}", self.url(upload.name));
        self.send("PUT", &url, Vec::new(), &RequestBody::File(body.clone()))?;
        Ok(String::new())
    }

    fn complete_multipart(
        &self,
        upload: &Upload<'_>,
        multipart: &Multipart,
        _etags: &[String],
    ) -> Result<()> {
        let mut xml = String::from("<BlockList>");
        for id in &multipart.block_ids {
            xml.push_str(&format!("<Latest>{id}</Latest>"));
        }
        xml.push_str("</BlockList>");
        let mut headers = vec![(
            "x-ms-blob-content-encoding".to_string(),
            "utf-8".to_string(),
        )];
        if let Some(md5) = upload.md5 {
            headers.push(("x-ms-blob-content-md5".into(), md5.to_string()));
        }
        headers.extend(Self::metadata(upload));
        let url = format!("{}?comp=blocklist", self.url(upload.name));
        self.send("PUT", &url, headers, &RequestBody::Bytes(xml.into_bytes()))
            .map(drop)
    }

    fn get(
        &self,
        download: &Download<'_>,
        range: Option<(u64, Option<u64>)>,
        out: &mut dyn Write,
    ) -> Result<Option<Metadata>> {
        let headers = range
            .map(|(first, last)| {
                let value = match last {
                    Some(last) => format!("bytes={first}-{last}"),
                    None => format!("bytes={first}-"),
                };
                vec![("Range".to_string(), value)]
            })
            .unwrap_or_default();
        let mut response =
            self.send("GET", &self.url(download.name), headers, &RequestBody::None)?;
        copy_body(&mut response, out)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_data_round_trips() {
        let enc = Metadata {
            key: "k".into(),
            iv: "i".into(),
            matdesc: "m".into(),
        };
        let data = encryption_data(&enc, "AES_CBC_128");
        assert!(data.starts_with(r#"{"EncryptionMode": "FullBlob", "WrappedContentKey": {"KeyId": "symmKey1", "EncryptedKey": "k""#));
        assert_eq!(parse_encryption_data(&data, Some("m")), Some(enc));
        assert_eq!(parse_encryption_data("null", None), None);
        assert_eq!(parse_encryption_data("{", None), None);
    }

    #[test]
    fn urls() {
        let http = Http::new(super::super::storage::backoff);
        let requery = |_: &str| Ok(serde_json::Value::Null);
        let creds = Credentials::new(&serde_json::json!({}), "PUT", &requery);
        let azure = Azure::new(
            &serde_json::json!({"location": "cont/a/b", "storageAccount": "acct", "endPoint": "blob.core.windows.net"}),
            &http,
            &creds,
            None,
        );
        assert_eq!(
            azure.url("f 1.gz"),
            "https://acct.blob.core.windows.net/cont/a/b/f%201.gz"
        );
    }
}
