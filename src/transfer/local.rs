//! `LOCAL_FS` stages (connector `local_storage_client.py`): a directory on this machine. Used by
//! tests and on-premises deployments.

use super::crypto::Metadata;
use super::storage::{Body, Download, Header, Multipart, Storage, Upload, file_error};
use crate::error::{Error, ErrorKind, Result};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

pub(crate) struct LocalFs {
    root: PathBuf,
}

impl LocalFs {
    pub(crate) fn new(location: &str, home: Option<&Path>) -> Result<Self> {
        let root = crate::config::expand_user_with(location, home);
        std::fs::create_dir_all(&root).map_err(file_error)?;
        Ok(Self { root })
    }

    /// The stage file for a name: only its base name, inside the stage directory.
    fn target(&self, name: &str) -> PathBuf {
        let base = name.rsplit('/').next().unwrap_or(name);
        self.root.join(base)
    }
}

impl LocalFs {
    /// The stage file a download names (the connector keeps its sub-directories), refusing any
    /// name that would leave the stage directory.
    fn stage_path(&self, name: &str) -> Result<PathBuf> {
        let relative = name.trim_start_matches('/');
        let escapes = Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir));
        if escapes {
            return Err(Error::new(
                ErrorKind::Client,
                format!(
                    "Refusing to read '{}': it is outside the stage directory.",
                    crate::render::sanitize::sanitize_for_terminal(name)
                ),
            ));
        }
        Ok(self.root.join(relative))
    }
}

impl Storage for LocalFs {
    fn chunk_size(&self, _size: u64) -> Option<u64> {
        None
    }

    fn head(&self, name: &str, _presigned_url: Option<&str>) -> Result<Option<Header>> {
        let path = self.target(name);
        Ok(std::fs::metadata(&path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map(|m| Header {
                size: Some(m.len()),
                encryption: None,
            }))
    }

    fn put(&self, upload: &Upload<'_>, body: &Body) -> Result<()> {
        let mut reader = body.open()?;
        let mut out = std::fs::File::create(self.target(upload.name)).map_err(file_error)?;
        std::io::copy(&mut reader, &mut out).map_err(file_error)?;
        Ok(())
    }

    fn put_part(
        &self,
        upload: &Upload<'_>,
        _: &Multipart,
        _: usize,
        body: &Body,
    ) -> Result<String> {
        self.put(upload, body).map(|()| String::new())
    }

    fn get(
        &self,
        download: &Download<'_>,
        range: Option<(u64, Option<u64>)>,
        out: &mut dyn Write,
    ) -> Result<Option<Metadata>> {
        let path = self.stage_path(download.name)?;
        let mut file = std::fs::File::open(path).map_err(file_error)?;
        let (first, last) = range.unwrap_or((0, None));
        file.seek(SeekFrom::Start(first)).map_err(file_error)?;
        match last {
            Some(last) => {
                let mut part = std::io::Read::take(file, last + 1 - first);
                std::io::copy(&mut part, out).map_err(file_error)?;
            }
            None => {
                std::io::copy(&mut file, out).map_err(file_error)?;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_head_and_ranged_get() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        let fs = LocalFs::new(stage.to_str().unwrap(), None).unwrap();
        let src = dir.path().join("src");
        std::fs::write(&src, b"0123456789").unwrap();
        let upload = Upload {
            name: "sub/f.txt",
            digest: "d",
            encryption: None,
            md5: None,
            compression: None,
            presigned_url: None,
        };
        let body = Body {
            path: src,
            offset: 2,
            len: 5,
        };
        assert!(fs.head("f.txt", None).unwrap().is_none());
        fs.put_part(&upload, &Multipart::default(), 0, &body)
            .unwrap();
        assert_eq!(fs.head("f.txt", None).unwrap().unwrap().size, Some(5));
        assert_eq!(fs.chunk_size(1), None);
        let download = Download {
            name: "/f.txt",
            presigned_url: None,
        };
        let mut out = Vec::new();
        fs.get(&download, Some((1, Some(2))), &mut out).unwrap();
        assert_eq!(out, b"34");
        out.clear();
        fs.get(&download, Some((3, None)), &mut out).unwrap();
        assert_eq!(out, b"56");
        let missing = Download {
            name: "none",
            presigned_url: None,
        };
        assert!(fs.get(&missing, None, &mut out).is_err());
        // Nothing outside the root is read, however the name is spelled.
        std::fs::write(dir.path().join("secret"), b"top").unwrap();
        for name in ["../secret", "/../secret", "a/../../secret", "..", "a/.."] {
            let escape = Download {
                name,
                presigned_url: None,
            };
            out.clear();
            let err = fs.get(&escape, None, &mut out).unwrap_err();
            assert!(
                err.message().contains("outside the stage directory"),
                "{name}"
            );
            assert!(out.is_empty());
        }
        let home = LocalFs::new("~/st", Some(dir.path())).unwrap();
        assert!(home.root.ends_with("st"));
    }
}
