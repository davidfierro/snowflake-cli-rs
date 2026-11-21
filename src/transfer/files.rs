//! Local files of a `PUT`: wildcard expansion, compression detection, gzip and digest
//! (connector `file_transfer_agent.py`, `file_compression_type.py`, `file_util.py`).

use crate::error::{Error, ErrorKind, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Connector error codes (`errorcode.py`).
pub(crate) const ER_FILE_NOT_EXISTS: u32 = 253006;
pub(crate) const ER_COMPRESSION_NOT_SUPPORTED: u32 = 253007;

/// A compression type of the connector's table.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Compression {
    pub name: &'static str,
    pub extension: &'static str,
    mime_type: &'static str,
    subtypes: &'static [&'static str],
    pub supported: bool,
}

pub(crate) const GZIP: Compression = Compression {
    name: "GZIP",
    extension: ".gz",
    mime_type: "application",
    subtypes: &["gzip", "x-gzip"],
    supported: true,
};

const TYPES: [Compression; 13] = [
    GZIP,
    Compression {
        name: "DEFLATE",
        extension: ".deflate",
        mime_type: "application",
        subtypes: &["zlib", "deflate"],
        supported: true,
    },
    Compression {
        name: "RAW_DEFLATE",
        extension: ".raw_deflate",
        mime_type: "application",
        subtypes: &["raw_deflate"],
        supported: true,
    },
    Compression {
        name: "BZIP2",
        extension: ".bz2",
        mime_type: "application",
        subtypes: &["bzip2", "x-bzip2", "x-bz2", "x-bzip", "bz2"],
        supported: true,
    },
    Compression {
        name: "LZIP",
        extension: ".lz",
        mime_type: "application",
        subtypes: &["lzip", "x-lzip"],
        supported: false,
    },
    Compression {
        name: "LZMA",
        extension: ".lzma",
        mime_type: "application",
        subtypes: &["lzma", "x-lzma"],
        supported: false,
    },
    Compression {
        name: "LZO",
        extension: ".lzo",
        mime_type: "application",
        subtypes: &["lzo", "x-lzo"],
        supported: false,
    },
    Compression {
        name: "XZ",
        extension: ".xz",
        mime_type: "application",
        subtypes: &["xz", "x-xz"],
        supported: false,
    },
    Compression {
        name: "COMPRESS",
        extension: ".Z",
        mime_type: "application",
        subtypes: &["compress", "x-compress"],
        supported: false,
    },
    Compression {
        name: "PARQUET",
        extension: ".parquet",
        mime_type: "snowflake",
        subtypes: &["parquet"],
        supported: true,
    },
    Compression {
        name: "ZSTD",
        extension: ".zst",
        mime_type: "application",
        subtypes: &["zstd", "x-zstd"],
        supported: true,
    },
    Compression {
        name: "BROTLI",
        extension: ".br",
        mime_type: "application",
        subtypes: &["br", "x-br"],
        supported: true,
    },
    Compression {
        name: "ORC",
        extension: ".orc",
        mime_type: "snowflake",
        subtypes: &["orc"],
        supported: true,
    },
];

/// `lookup_by_mime_sub_type`.
fn lookup(subtype: &str) -> Option<&'static Compression> {
    let lower = subtype.to_lowercase();
    TYPES
        .iter()
        .find(|t| t.subtypes.iter().any(|s| *s == lower))
}

impl Compression {
    /// Python's `repr()` of the `CompressionType` named tuple.
    fn repr(&self) -> String {
        let subtypes: Vec<String> = self.subtypes.iter().map(|s| format!("'{s}'")).collect();
        format!(
            "CompressionType(name='{}', file_extension='{}', mime_type='{}', mime_subtypes=[{}], is_supported={})",
            self.name,
            self.extension,
            self.mime_type,
            subtypes.join(", "),
            if self.supported { "True" } else { "False" }
        )
    }
}

/// A connector `ProgrammingError`/`OperationalError` as `snow` prints it: `<code>: <code>: …`.
/// `snow` exits 5 for them with `--enhanced-exit-codes`, so they are `Sql` errors.
pub(crate) fn connector_error(code: u32, message: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Sql, format!("{code}: {code}: {message}"))
}

fn not_supported(compression: Option<&Compression>) -> Error {
    let shown = compression.map_or_else(|| "None".to_string(), Compression::repr);
    connector_error(
        ER_COMPRESSION_NOT_SUPPORTED,
        format!("Feature is not supported: {shown}"),
    )
}

/// How the source compression of every file is decided (`_process_file_compression_type`).
pub(crate) enum SourceCompression {
    AutoDetect,
    None,
    Given(&'static Compression),
}

/// The `sourceCompression` of the answer: `auto_detect`, `none` or a mime subtype.
pub(crate) fn source_compression(value: &str) -> Result<SourceCompression> {
    match value.to_lowercase().as_str() {
        "auto_detect" => Ok(SourceCompression::AutoDetect),
        "none" | "" => Ok(SourceCompression::None),
        other => match lookup(other) {
            Some(t) if t.supported => Ok(SourceCompression::Given(t)),
            found => Err(not_supported(found)),
        },
    }
}

/// The compression of one file: `None` when it is not compressed.
pub(crate) fn detect(
    path: &Path,
    mode: &SourceCompression,
) -> Result<Option<&'static Compression>> {
    let found = match mode {
        SourceCompression::None => return Ok(None),
        SourceCompression::Given(t) => return Ok(Some(t)),
        SourceCompression::AutoDetect => match mime_encoding(path) {
            Some(encoding) => lookup(encoding),
            None => magic(path)?.and_then(lookup),
        },
    };
    match found {
        Some(t) if !t.supported => Err(not_supported(Some(t))),
        other => Ok(other),
    }
}

/// Python's `mimetypes.guess_type(path)[1]`: the encoding from the extension.
fn mime_encoding(path: &Path) -> Option<&'static str> {
    let mut name = path.file_name()?.to_string_lossy().into_owned();
    // `suffix_map` (case-insensitive), applied repeatedly.
    loop {
        let ext = extension(&name).to_lowercase();
        let replacement = match ext.as_str() {
            ".svgz" => ".svg.gz",
            ".tgz" | ".taz" | ".tz" => ".tar.gz",
            ".tbz2" => ".tar.bz2",
            ".txz" => ".tar.xz",
            _ => break,
        };
        name.truncate(name.len() - ext.len());
        name.push_str(replacement);
    }
    // `encodings_map` (case-sensitive).
    match extension(&name) {
        ".gz" => Some("gzip"),
        ".Z" => Some("compress"),
        ".bz2" => Some("bzip2"),
        ".xz" => Some("xz"),
        ".br" => Some("br"),
        _ => None,
    }
}

/// `posixpath.splitext` extension: from the last dot, unless the name only starts with dots.
fn extension(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if name[..i].chars().any(|c| c != '.') => &name[i..],
        _ => "",
    }
}

/// The first four bytes: ORC, Parquet or zstd.
fn magic(path: &Path) -> Result<Option<&'static str>> {
    let mut head = Vec::with_capacity(4);
    std::fs::File::open(path)
        .and_then(|f| f.take(4).read_to_end(&mut head))
        .map_err(|e| read_error(path, e))?;
    Ok(if head.starts_with(b"ORC") {
        Some("orc")
    } else if head == b"PAR1" {
        Some("parquet")
    } else if head == [0x28, 0xB5, 0x2F, 0xFD] {
        Some("zstd")
    } else {
        None
    })
}

fn read_error(path: &Path, e: std::io::Error) -> Error {
    Error::new(
        ErrorKind::Client,
        format!("Could not read: {}", path.display()),
    )
    .with_source(e)
}

/// The local files of a `PUT` (`_expand_filenames`): `~` expanded, made absolute, globbed as
/// Python's `glob.glob` (a leading dot is never matched by a wildcard).
pub(crate) fn expand(locations: &[String], home: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for location in locations {
        let mut path = crate::config::expand_user_with(location, home);
        if !path.is_absolute()
            && let Ok(cwd) = std::env::current_dir()
        {
            path = normalize(&cwd.join(path));
        }
        let pattern = path.to_string_lossy().into_owned();
        let options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: true,
        };
        match glob::glob_with(&pattern, options) {
            Ok(paths) => out.extend(paths.filter_map(std::result::Result::ok)),
            // An invalid pattern (an unclosed `[`) is a literal name for Python.
            Err(_) => {
                if path.exists() {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// `os.path.normpath` of an absolute path: `.` and `..` resolved lexically.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Gzips `src` into `dst` as the connector does: the header has mtime 0 and, in place of the
/// file name Python writes (`<name>_c`), as many spaces (`normalize_gzip_header`), so the sizes
/// match `snow`'s.
pub(crate) fn gzip(src: &Path, dst: &Path, base_name: &str) -> Result<u64> {
    let mut input = std::fs::File::open(src).map_err(|e| read_error(src, e))?;
    let file = create_private(dst)?;
    let mut out = std::io::BufWriter::new(file);
    let fname: Option<usize> = base_name
        .chars()
        .all(|c| (c as u32) < 256)
        .then(|| base_name.chars().count() + 2);
    let mut write = |out: &mut std::io::BufWriter<std::fs::File>| -> std::io::Result<u64> {
        let flags = if fname.is_some() { 0x08 } else { 0x00 };
        out.write_all(&[0x1f, 0x8b, 0x08, flags, 0, 0, 0, 0, 0x02, 0xff])?;
        if let Some(len) = fname {
            out.write_all(&vec![b' '; len])?;
            out.write_all(&[0])?;
        }
        let mut crc = flate2::Crc::new();
        let mut encoder =
            flate2::write::DeflateEncoder::new(&mut *out, flate2::Compression::best());
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            crc.update(&buffer[..n]);
            encoder.write_all(&buffer[..n])?;
        }
        encoder.finish()?;
        out.write_all(&crc.sum().to_le_bytes())?;
        out.write_all(&crc.amount().to_le_bytes())?;
        out.flush()?;
        Ok(out.get_ref().metadata()?.len())
    };
    write(&mut out).map_err(|e| {
        Error::new(ErrorKind::Client, "Could not compress a file for upload.").with_source(e)
    })
}

/// Base64 SHA-256 of a file (`sfc-digest`), and its size.
pub(crate) fn digest(path: &Path) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path).map_err(|e| read_error(path, e))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(|e| read_error(path, e))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buffer[..n]);
    }
    Ok((
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize()),
        size,
    ))
}

/// Base64 MD5 of a file (Azure's `x-ms-blob-content-md5`).
pub(crate) fn md5(path: &Path) -> Result<String> {
    use md5::Digest as _;
    let mut file = std::fs::File::open(path).map_err(|e| read_error(path, e))?;
    let mut hasher = md5::Md5::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| read_error(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(hasher.finalize()))
}

/// Creates a new file readable and writable by its owner only.
pub(crate) fn create_private(path: &Path) -> Result<std::fs::File> {
    let mut options = crate::fsutil::private_options();
    options.write(true).create_new(true);
    options.open(path).map_err(|e| {
        Error::new(
            ErrorKind::Client,
            format!("Could not create: {}", path.display()),
        )
        .with_source(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn mime_encodings_follow_python() {
        for (name, encoding) in [
            ("a.csv.gz", Some("gzip")),
            ("a.GZ", None),
            ("a.tgz", Some("gzip")),
            ("a.TGZ", Some("gzip")),
            ("a.svgz", Some("gzip")),
            ("a.bz2", Some("bzip2")),
            ("a.xz", Some("xz")),
            ("a.Z", Some("compress")),
            ("a.br", Some("br")),
            ("a.zst", None),
            ("a.gz.csv", None),
            (".gz", None),
            ("a.txz", Some("xz")),
            ("a.tbz2", Some("bzip2")),
        ] {
            assert_eq!(mime_encoding(Path::new(name)), encoding, "{name}");
        }
    }

    #[test]
    fn detection_uses_extension_then_magic_bytes() {
        let dir = temp();
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.path().join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        let auto = SourceCompression::AutoDetect;
        let name = |p: &Path| detect(p, &auto).unwrap().map(|t| t.name);
        assert_eq!(name(&write("a.csv", b"a,b")), None);
        assert_eq!(name(&write("a.csv.gz", b"x")), Some("GZIP"));
        assert_eq!(name(&write("a.orc", b"ORCx")), Some("ORC"));
        assert_eq!(name(&write("a.bin", b"PAR1")), Some("PARQUET"));
        assert_eq!(
            name(&write("a.zst", &[0x28, 0xB5, 0x2F, 0xFD])),
            Some("ZSTD")
        );
        assert_eq!(name(&write("a.br", b"x")), Some("BROTLI"));
        let err = detect(&write("a.xz", b"x"), &auto).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Sql);
        assert_eq!(
            err.message(),
            "253007: 253007: Feature is not supported: CompressionType(name='XZ', \
             file_extension='.xz', mime_type='application', mime_subtypes=['xz', 'x-xz'], \
             is_supported=False)"
        );
        let given = source_compression("GZIP").unwrap();
        assert_eq!(
            detect(&write("b.csv", b"x"), &given)
                .unwrap()
                .map(|t| t.name),
            Some("GZIP")
        );
        assert!(
            detect(&write("c.gz", b"x"), &SourceCompression::None)
                .unwrap()
                .is_none()
        );
        assert!(detect(&dir.path().join("missing.bin"), &auto).is_err());
    }

    #[test]
    fn source_compression_values() {
        assert!(matches!(
            source_compression("auto_detect").unwrap(),
            SourceCompression::AutoDetect
        ));
        assert!(matches!(
            source_compression("NONE").unwrap(),
            SourceCompression::None
        ));
        assert!(matches!(
            source_compression("bz2").unwrap(),
            SourceCompression::Given(t) if t.name == "BZIP2"
        ));
        assert_eq!(
            source_compression("brotli").err().unwrap().message(),
            "253007: 253007: Feature is not supported: None"
        );
        assert!(source_compression("lzma").is_err());
    }

    #[test]
    fn gzip_matches_the_connector_layout() {
        let dir = temp();
        let src = dir.path().join("f1.csv");
        std::fs::write(&src, b"a,b\n1,2\n").unwrap();
        let dst = dir.path().join("out.gz");
        // snow uploads this 8-byte file as a 37-byte gzip (see the goldens).
        assert_eq!(gzip(&src, &dst, "f1.csv").unwrap(), 37);
        let bytes = std::fs::read(&dst).unwrap();
        assert_eq!(&bytes[..4], &[0x1f, 0x8b, 0x08, 0x08]);
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
        assert_eq!(&bytes[10..19], b"        \0");
        let mut text = String::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "a,b\n1,2\n");
        // A name Python cannot encode as Latin-1 gets no name field.
        let dst2 = dir.path().join("out2.gz");
        gzip(&src, &dst2, "€.csv").unwrap();
        assert_eq!(std::fs::read(&dst2).unwrap()[3], 0);
        assert!(gzip(&dir.path().join("missing"), &dir.path().join("o3"), "m").is_err());
    }

    #[test]
    fn digests() {
        let dir = temp();
        let p = dir.path().join("x");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            digest(&p).unwrap(),
            (
                "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=".to_string(),
                3
            )
        );
        assert_eq!(md5(&p).unwrap(), "kAFQmDzST7DWlj99KOF/cg==");
        assert!(digest(&dir.path().join("missing")).is_err());
        assert!(md5(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn expansion_globs_like_python() {
        let dir = temp();
        for name in ["a.csv", "b.csv", ".hidden.csv", "c.txt"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let pattern = format!("{}/*.csv", dir.path().display());
        let mut found = expand(&[pattern], None);
        found.sort();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.csv", "b.csv"]);
        let literal = format!("{}/c.txt", dir.path().display());
        assert_eq!(expand(&[literal], None).len(), 1);
        assert!(expand(&[format!("{}/none", dir.path().display())], None).is_empty());
        let home_pattern = "~/c.txt".to_string();
        assert_eq!(expand(&[home_pattern], Some(dir.path())).len(), 1);
        let bracket = format!("{}/[x", dir.path().display());
        assert!(expand(&[bracket], None).is_empty());
    }

    #[test]
    fn helpers() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(extension("a.b.c"), ".c");
        assert_eq!(extension("..x"), "");
        assert_eq!(
            GZIP.repr(),
            "CompressionType(name='GZIP', file_extension='.gz', mime_type='application', \
             mime_subtypes=['gzip', 'x-gzip'], is_supported=True)"
        );
    }
}
