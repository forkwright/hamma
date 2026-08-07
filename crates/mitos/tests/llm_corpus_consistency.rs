//! Regression test for hamma#85: the LLM discovery corpus classified the
//! library-only `dictyon` crate as a binary/CLI surface, diverging from
//! what Cargo actually builds. This test makes `_llm/architecture.toml`'s
//! declared interface `kind` the checked side of that relationship, with
//! Cargo target metadata as the source of truth.

use std::fs;
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};

/// Failure modes for reading and cross-checking the LLM discovery corpus.
#[derive(Debug, Snafu)]
#[non_exhaustive]
enum CorpusCheckError {
    #[snafu(display("failed to read {path:?}: {source}"))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse {path:?} as TOML: {source}"))]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[snafu(display("{message}"))]
    Shape { message: String },
}

fn workspace_root() -> PathBuf {
    // NOTE: CARGO_MANIFEST_DIR is `<repo>/crates/mitos`; the workspace
    // root is two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("../.."), Path::to_path_buf)
}

fn read_toml(path: &Path) -> Result<toml::Value, CorpusCheckError> {
    let text = fs::read_to_string(path).context(ReadSnafu { path })?;
    toml::from_str(&text).context(ParseSnafu { path })
}

/// Cargo considers a crate a binary/CLI surface when it declares an
/// explicit `[[bin]]` target, or ships the implicit `src/main.rs`/`src/bin/`
/// auto-discovery targets — the same rule `cargo metadata` uses.
fn has_bin_target(crate_dir: &Path, manifest_path: &Path) -> Result<bool, CorpusCheckError> {
    let manifest = read_toml(manifest_path)?;

    let declares_bin_section = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .is_some_and(|bins| !bins.is_empty());

    let has_main_rs = crate_dir.join("src/main.rs").is_file();

    let has_bin_dir_entries = fs::read_dir(crate_dir.join("src/bin"))
        .map(|mut entries| entries.find_map(Result::ok).is_some())
        .unwrap_or(false);

    Ok(declares_bin_section || has_main_rs || has_bin_dir_entries)
}

#[test]
fn llm_corpus_interface_kind_matches_cargo_targets() -> Result<(), CorpusCheckError> {
    let root = workspace_root();
    let corpus_path = root.join("_llm/architecture.toml");
    let corpus = read_toml(&corpus_path)?;

    let interfaces = corpus
        .get("interfaces")
        .and_then(toml::Value::as_array)
        .cloned()
        .ok_or_else(|| {
            ShapeSnafu {
                message: format!("{corpus_path:?} has no [[interfaces]] entries to check"),
            }
            .build()
        })?;

    assert!(
        !interfaces.is_empty(),
        "{corpus_path:?} declares zero interfaces — nothing to cross-check"
    );

    for interface in &interfaces {
        let name = interface
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("<unnamed interface>");
        let path = interface
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                ShapeSnafu {
                    message: format!("interface {name:?} has no path"),
                }
                .build()
            })?;
        let kind = interface
            .get("kind")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                ShapeSnafu {
                    message: format!("interface {name:?} has no kind"),
                }
                .build()
            })?;

        let crate_dir = root.join(path);
        let manifest_path = crate_dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            // A corpus entry may name a planned crate that has not landed
            // in the workspace yet; there is no Cargo truth to check it
            // against until it does.
            continue;
        }

        let has_bin = has_bin_target(&crate_dir, &manifest_path)?;
        match kind {
            "cli" => assert!(
                has_bin,
                "{corpus_path:?} declares interface {name:?} (path={path}) as \
                 kind=\"cli\", but Cargo exposes no [[bin]] target, src/main.rs, \
                 or src/bin/ for it — it is a library. Fix the corpus entry or \
                 land the real binary target."
            ),
            "lib" => assert!(
                !has_bin,
                "{corpus_path:?} declares interface {name:?} (path={path}) as \
                 kind=\"lib\", but Cargo exposes a binary target for it — update \
                 the corpus entry to kind=\"cli\"."
            ),
            other => {
                return ShapeSnafu {
                    message: format!(
                        "interface {name:?} has unrecognized kind {other:?}; \
                         extend this test to check the new kind against Cargo truth"
                    ),
                }
                .fail();
            }
        }
    }

    Ok(())
}
