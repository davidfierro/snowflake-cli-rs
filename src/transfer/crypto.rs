//! Client-side encryption of stage files (ADR 0005, Decision 5; connector `encryption_util.py`):
//! a random file key and IV, AES-CBC/PKCS#7 content, the file key wrapped with AES-ECB under the
//! stage master key. Files are streamed in 64 KiB blocks.

use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::io::{Read, Write};
use zeroize::Zeroizing;

const BLOCK: usize = 16;
const BUFFER: usize = 64 * 1024;

/// `encryptionMaterial` of a `PUT`/`GET` answer.
#[derive(Debug, Clone)]
pub(crate) struct Material {
    /// Base64 `queryStageMasterKey`.
    pub master_key: Secret,
    pub query_id: String,
    pub smk_id: String,
}

impl Material {
    pub(crate) fn from_json(value: &serde_json::Value) -> Option<Self> {
        let smk_id = match &value["smkId"] {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => return None,
        };
        Some(Self {
            master_key: Secret::new(value["queryStageMasterKey"].as_str()?),
            query_id: value["queryId"].as_str().unwrap_or_default().to_string(),
            smk_id,
        })
    }

    fn key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let key = Zeroizing::new(STANDARD.decode(self.master_key.expose()).map_err(|_| {
            Error::new(
                ErrorKind::Communication,
                "The stage master key is not base64.",
            )
        })?);
        check_size(key.len())?;
        Ok(key)
    }
}

/// The per-file metadata stored next to the object (`x-amz-key`, `x-amz-iv`, `matdesc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Metadata {
    /// Base64 wrapped file key.
    pub key: String,
    /// Base64 IV.
    pub iv: String,
    pub matdesc: String,
}

fn check_size(len: usize) -> Result<()> {
    if matches!(len, 16 | 24 | 32) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Communication,
            format!("Unsupported encryption key size: {} bits.", len * 8),
        ))
    }
}

fn crypto_error() -> Error {
    Error::new(ErrorKind::Client, "Could not decrypt a downloaded file.")
}

fn io_error(e: std::io::Error) -> Error {
    Error::new(
        ErrorKind::Client,
        "Could not read or write a transferred file.",
    )
    .with_source(e)
}

/// AES-CBC in one of the three key sizes.
enum CbcEncrypt {
    A128(cbc::Encryptor<aes::Aes128>),
    A192(cbc::Encryptor<aes::Aes192>),
    A256(cbc::Encryptor<aes::Aes256>),
}

enum CbcDecrypt {
    A128(cbc::Decryptor<aes::Aes128>),
    A192(cbc::Decryptor<aes::Aes192>),
    A256(cbc::Decryptor<aes::Aes256>),
}

impl CbcEncrypt {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        let bad = |_| crypto_error();
        Ok(match key.len() {
            16 => Self::A128(cbc::Encryptor::new_from_slices(key, iv).map_err(bad)?),
            24 => Self::A192(cbc::Encryptor::new_from_slices(key, iv).map_err(bad)?),
            _ => Self::A256(cbc::Encryptor::new_from_slices(key, iv).map_err(bad)?),
        })
    }

    /// Encrypts whole blocks in place.
    fn blocks(&mut self, data: &mut [u8]) {
        for block in data.as_chunks_mut::<BLOCK>().0 {
            let block = block.into();
            match self {
                Self::A128(c) => c.encrypt_block(block),
                Self::A192(c) => c.encrypt_block(block),
                Self::A256(c) => c.encrypt_block(block),
            }
        }
    }
}

impl CbcDecrypt {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        let bad = |_| crypto_error();
        Ok(match key.len() {
            16 => Self::A128(cbc::Decryptor::new_from_slices(key, iv).map_err(bad)?),
            24 => Self::A192(cbc::Decryptor::new_from_slices(key, iv).map_err(bad)?),
            32 => Self::A256(cbc::Decryptor::new_from_slices(key, iv).map_err(bad)?),
            _ => return Err(crypto_error()),
        })
    }

    fn blocks(&mut self, data: &mut [u8]) {
        for block in data.as_chunks_mut::<BLOCK>().0 {
            let block = block.into();
            match self {
                Self::A128(c) => c.decrypt_block(block),
                Self::A192(c) => c.decrypt_block(block),
                Self::A256(c) => c.decrypt_block(block),
            }
        }
    }
}

/// AES-ECB over whole blocks, in place: the key wrapping.
fn ecb(key: &[u8], data: &mut [u8], encrypt: bool) -> Result<()> {
    macro_rules! run {
        ($cipher:ty) => {{
            if encrypt {
                let mut c =
                    ecb::Encryptor::<$cipher>::new_from_slice(key).map_err(|_| crypto_error())?;
                for block in data.as_chunks_mut::<BLOCK>().0 {
                    c.encrypt_block(block.into());
                }
            } else {
                let mut c =
                    ecb::Decryptor::<$cipher>::new_from_slice(key).map_err(|_| crypto_error())?;
                for block in data.as_chunks_mut::<BLOCK>().0 {
                    c.decrypt_block(block.into());
                }
            }
        }};
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        32 => run!(aes::Aes256),
        _ => return Err(crypto_error()),
    }
    Ok(())
}

fn pad(data: &mut Vec<u8>) {
    let n = BLOCK - data.len() % BLOCK;
    data.extend(std::iter::repeat_n(n as u8, n));
}

fn unpad(data: &[u8]) -> Result<&[u8]> {
    let n = *data.last().ok_or_else(crypto_error)? as usize;
    if n == 0
        || n > BLOCK
        || n > data.len()
        || data[data.len() - n..].iter().any(|&b| b as usize != n)
    {
        return Err(crypto_error());
    }
    Ok(&data[..data.len() - n])
}

/// Random bytes from the OS.
pub(crate) fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut bytes).map_err(|_| {
        Error::new(
            ErrorKind::Client,
            "The system random number generator failed.",
        )
    })?;
    Ok(bytes)
}

/// Encrypts `src` into `out` with a fresh file key and IV; returns the metadata and the size
/// written.
pub(crate) fn encrypt(
    material: &Material,
    src: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<(Metadata, u64)> {
    let master = material.key()?;
    let file_key = random(master.len())?;
    let iv = random(BLOCK)?;
    encrypt_with(material, &file_key, &iv, src, out)
}

/// [`encrypt`] with a given file key and IV (known-answer tests).
fn encrypt_with(
    material: &Material,
    file_key: &[u8],
    iv: &[u8],
    src: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<(Metadata, u64)> {
    let master = material.key()?;
    let mut cbc = CbcEncrypt::new(file_key, iv)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(BUFFER + BLOCK));
    let mut written = 0u64;
    let mut chunk = vec![0u8; BUFFER];
    loop {
        let n = read_full(src, &mut chunk).map_err(io_error)?;
        buffer.extend_from_slice(&chunk[..n]);
        if n < BUFFER {
            pad(&mut buffer);
            cbc.blocks(&mut buffer);
            out.write_all(&buffer).map_err(io_error)?;
            written += buffer.len() as u64;
            break;
        }
        // Keep a partial block for the next round (none: BUFFER is a multiple of BLOCK).
        cbc.blocks(&mut buffer);
        out.write_all(&buffer).map_err(io_error)?;
        written += buffer.len() as u64;
        buffer.clear();
    }
    let mut wrapped = Zeroizing::new(file_key.to_vec());
    pad(&mut wrapped);
    ecb(&master, &mut wrapped, true)?;
    // `matdesc_to_unicode`: this key order, compact separators.
    let quote = |s: &str| serde_json::Value::from(s).to_string();
    let matdesc = format!(
        "{{\"queryId\":{},\"smkId\":{},\"keySize\":\"{}\"}}",
        quote(&material.query_id),
        quote(&material.smk_id),
        master.len() * 8
    );
    Ok((
        Metadata {
            key: STANDARD.encode(&*wrapped),
            iv: STANDARD.encode(iv),
            matdesc,
        },
        written,
    ))
}

/// Reads until `buffer` is full or the input ends.
fn read_full(src: &mut dyn Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match src.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Decrypts `src` into `out` (the reverse of [`encrypt`]); returns the size written.
pub(crate) fn decrypt(
    metadata: &Metadata,
    material: &Material,
    src: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<u64> {
    let master = material.key()?;
    let mut file_key = Zeroizing::new(STANDARD.decode(&metadata.key).map_err(|_| crypto_error())?);
    let iv = STANDARD.decode(&metadata.iv).map_err(|_| crypto_error())?;
    if file_key.is_empty() || file_key.len() % BLOCK != 0 {
        return Err(crypto_error());
    }
    ecb(&master, &mut file_key, false)?;
    let file_key = Zeroizing::new(unpad(&file_key)?.to_vec());
    let mut cbc = CbcDecrypt::new(&file_key, &iv)?;
    let mut chunk = vec![0u8; BUFFER];
    // The last decrypted block is held back until the input ends: it carries the padding.
    let mut held: Option<Vec<u8>> = None;
    let mut written = 0u64;
    loop {
        let n = read_full(src, &mut chunk).map_err(io_error)?;
        if n == 0 {
            break;
        }
        if n % BLOCK != 0 {
            return Err(crypto_error());
        }
        if let Some(previous) = held.take() {
            out.write_all(&previous).map_err(io_error)?;
            written += previous.len() as u64;
        }
        let data = &mut chunk[..n];
        cbc.blocks(data);
        held = Some(data.to_vec());
        if n < BUFFER {
            break;
        }
    }
    let last = held.ok_or_else(crypto_error)?;
    let plain = unpad(&last)?;
    out.write_all(plain).map_err(io_error)?;
    Ok(written + plain.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::hex;

    /// Known-answer vector produced once with Python `cryptography` following
    /// `encryption_util.py` (master key 16 × 0x01, file key 16 × 0x02, IV 16 × 0x03).
    const PLAIN: &[u8] = b"a,b\n1,2\n";
    const CIPHER_HEX: &str = "3020db6538d2f9d7bf982220f73e728b";
    const WRAPPED: &str = "F9YU83mpNZB36VV3/THCCmhDTTfX9p8OA7dbsVvJS2w=";

    fn material(len: usize) -> Material {
        Material {
            master_key: Secret::new(STANDARD.encode(vec![1u8; len])),
            query_id: "q".into(),
            smk_id: "7".into(),
        }
    }

    #[test]
    fn known_answer() {
        let mut out = Vec::new();
        let (meta, n) = encrypt_with(
            &material(16),
            &[2u8; 16],
            &[3u8; 16],
            &mut &PLAIN[..],
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 16);
        assert_eq!(hex(&out), CIPHER_HEX);
        assert_eq!(meta.key, WRAPPED);
        assert_eq!(meta.iv, STANDARD.encode([3u8; 16]));
        assert_eq!(
            meta.matdesc,
            r#"{"queryId":"q","smkId":"7","keySize":"128"}"#
        );
    }

    #[test]
    fn round_trips_for_every_key_size_and_length() {
        for key in [16, 24, 32] {
            for len in [
                0,
                1,
                15,
                16,
                17,
                BUFFER - 1,
                BUFFER,
                BUFFER + 1,
                3 * BUFFER + 5,
            ] {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut enc = Vec::new();
                let (meta, n) = encrypt(&material(key), &mut &plain[..], &mut enc).unwrap();
                assert_eq!(n as usize, enc.len());
                assert_eq!(enc.len(), (len / 16 + 1) * 16, "{key} {len}");
                let mut dec = Vec::new();
                let m = decrypt(&meta, &material(key), &mut &enc[..], &mut dec).unwrap();
                assert_eq!(dec, plain, "{key} {len}");
                assert_eq!(m as usize, len);
            }
        }
    }

    #[test]
    fn bad_inputs_fail() {
        let mut enc = Vec::new();
        let (meta, _) = encrypt(&material(16), &mut &b"hello"[..], &mut enc).unwrap();
        // Truncated ciphertext.
        assert!(decrypt(&meta, &material(16), &mut &enc[..5], &mut Vec::new()).is_err());
        // Empty ciphertext.
        assert!(decrypt(&meta, &material(16), &mut &b""[..], &mut Vec::new()).is_err());
        // Wrong master key: the unwrapped key has bad padding (or the content does).
        assert!(decrypt(&meta, &material(32), &mut &enc[..], &mut Vec::new()).is_err());
        let bad = Metadata {
            key: "!!".into(),
            ..meta.clone()
        };
        assert!(decrypt(&bad, &material(16), &mut &enc[..], &mut Vec::new()).is_err());
        let bad = Metadata {
            key: STANDARD.encode([1u8; 5]),
            ..meta
        };
        assert!(decrypt(&bad, &material(16), &mut &enc[..], &mut Vec::new()).is_err());
        let odd = Material {
            master_key: Secret::new(STANDARD.encode([1u8; 10])),
            ..material(16)
        };
        assert!(encrypt(&odd, &mut &b"x"[..], &mut Vec::new()).is_err());
        let not_b64 = Material {
            master_key: Secret::new("%%%"),
            ..material(16)
        };
        assert!(encrypt(&not_b64, &mut &b"x"[..], &mut Vec::new()).is_err());
        assert!(unpad(&[]).is_err());
        assert!(unpad(&[0u8; 16]).is_err());
    }

    #[test]
    fn material_from_json() {
        let m = Material::from_json(&serde_json::json!({
            "queryStageMasterKey": "a2V5", "queryId": "q", "smkId": 42
        }))
        .unwrap();
        assert_eq!(m.smk_id, "42");
        let m = Material::from_json(&serde_json::json!({
            "queryStageMasterKey": "a2V5", "smkId": "43"
        }))
        .unwrap();
        assert_eq!(m.smk_id, "43");
        assert!(Material::from_json(&serde_json::json!({"queryStageMasterKey": "a"})).is_none());
        assert!(Material::from_json(&serde_json::json!({"smkId": 1})).is_none());
    }
}
