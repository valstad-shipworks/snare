//! Where the shims come from: the same place as the `snare-interpose` the workspace's lock file
//! resolved, so a shim that depends on `snare-interpose` (by path within the snare repository)
//! and the code under test link one copy of it. Two copies of the interposer each install their
//! own hooks and keep their own sims, and a sim one of them runs is invisible to the other.
//!
//! - A `snare-interpose` from crates.io at version `X`: the shims, `snare` and `snare-interpose`
//!   all come from the snare repository at tag `vX`, the release that version was published from.
//! - From a path: the `shims/` directory of that checkout.
//! - From git: the same repository and reference (tag, branch or rev). Cargo tells git sources
//!   apart by their reference as well as their URL, so a shim taken at the commit a tag names
//!   would still be a second source.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The repository holding `shims/`. Cargo finds a git dependency's package by name anywhere in
/// the repository, so each shim resolves to its subdirectory.
pub(crate) const SNARE_GIT: &str = "https://github.com/valstad-shipworks/snare";

/// The packages of the snare repository published to crates.io that a shim can depend on.
const INTERPOSER: [&str; 2] = ["snare", "snare-interpose"];

/// A git reference, as a `[patch]` entry names it
/// ([The Cargo Book: Specifying dependencies from git repositories](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GitRef {
    Tag(String),
    Branch(String),
    Rev(String),
    /// The repository's default branch.
    Default,
}

/// Where the shims, and the snare packages they must agree with, come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// A local `shims/` directory.
    Path(PathBuf),
    /// A git repository at a reference. `interposer` when `snare` and `snare-interpose` must be
    /// patched from it too: the workspace takes them from crates.io.
    Git {
        url: String,
        reference: GitRef,
        interposer: bool,
    },
}

impl Source {
    /// The `--config` patch entries for `key` (a `[patch.crates-io]` key) from this source, where
    /// a shim's directory is `dir`.
    pub(crate) fn patch(&self, key: &str, dir: &str) -> Vec<String> {
        let entry = |field: &str, value: String| format!("patch.crates-io.{key}.{field}={value}");
        match self {
            Source::Path(shims) => vec![entry("path", toml_string(&shims.join(dir)))],
            Source::Git { url, reference, .. } => {
                let mut fields = vec![entry("git", format!("\"{url}\""))];
                match reference {
                    GitRef::Tag(tag) => fields.push(entry("tag", format!("\"{tag}\""))),
                    GitRef::Branch(branch) => fields.push(entry("branch", format!("\"{branch}\""))),
                    GitRef::Rev(rev) => fields.push(entry("rev", format!("\"{rev}\""))),
                    GitRef::Default => {}
                }
                fields
            }
        }
    }

    /// The patch entries that put `snare` and `snare-interpose` on this source as well, when the
    /// workspace would otherwise take them from crates.io.
    pub(crate) fn interposer_patches(&self) -> Vec<String> {
        match self {
            Source::Git {
                interposer: true, ..
            } => INTERPOSER
                .iter()
                .flat_map(|name| self.patch(name, name))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The snare release this source is pinned to: a git tag `vX.Y.Z`, or `None` for a path, a
    /// branch, a commit or a tag of another form.
    pub(crate) fn release(&self) -> Option<(u64, u64, u64)> {
        let Source::Git {
            reference: GitRef::Tag(tag),
            ..
        } = self
        else {
            return None;
        };
        let mut parts = tag.strip_prefix('v')?.splitn(3, '.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        Some((next()?, next()?, next()?))
    }

    /// A short description for `--dry-run`.
    pub(crate) fn describe(&self) -> String {
        match self {
            Source::Path(dir) => format!("shims from {}", dir.display()),
            Source::Git {
                url,
                reference,
                interposer,
            } => {
                let at = match reference {
                    GitRef::Tag(tag) => format!(" tag {tag}"),
                    GitRef::Branch(branch) => format!(" branch {branch}"),
                    GitRef::Rev(rev) => format!(" rev {rev}"),
                    GitRef::Default => String::new(),
                };
                let with = if *interposer {
                    ", with snare and snare-interpose"
                } else {
                    ""
                };
                format!("shims from {url}{at}{with}")
            }
        }
    }
}

/// The source to use: `shims_dir` or `shims_rev` when given, else the one the resolved
/// `snare-interpose` in `metadata` (`cargo metadata --format-version 1`) points to, else this
/// binary's own release tag `fallback`.
pub(crate) fn resolve(
    metadata: &Value,
    shims_dir: Option<&Path>,
    shims_rev: Option<&str>,
    fallback: &str,
) -> Result<Source, String> {
    if let Some(dir) = shims_dir {
        return Ok(Source::Path(dir.to_path_buf()));
    }
    let interposer = locked_interposer(metadata)?;
    if let Some(rev) = shims_rev {
        return Ok(Source::Git {
            url: SNARE_GIT.to_string(),
            reference: GitRef::Rev(rev.to_string()),
            interposer: !matches!(interposer, Some(Locked::Path(_) | Locked::Git { .. })),
        });
    }
    Ok(match interposer {
        Some(Locked::Registry(version)) => Source::Git {
            url: SNARE_GIT.to_string(),
            reference: GitRef::Tag(format!("v{version}")),
            interposer: true,
        },
        Some(Locked::Path(manifest)) => match repository_shims(&manifest) {
            Some(shims) => Source::Path(shims),
            None => {
                return Err(format!(
                    "snare-interpose comes from {}, which has no shims/ beside it; pass \
                     --shims-dir",
                    manifest.display()
                ));
            }
        },
        Some(Locked::Git { url, reference }) => Source::Git {
            url,
            reference,
            interposer: false,
        },
        None => Source::Git {
            url: SNARE_GIT.to_string(),
            reference: GitRef::Tag(fallback.to_string()),
            interposer: false,
        },
    })
}

/// Where the lock file put `snare-interpose`.
#[derive(Debug, PartialEq, Eq)]
enum Locked {
    /// crates.io, at this version.
    Registry(String),
    /// A local package, by its manifest.
    Path(PathBuf),
    Git {
        url: String,
        reference: GitRef,
    },
}

/// The `snare-interpose` package of the resolved graph, `None` when the workspace has none; an
/// error when it has several, since each would need its own shims.
fn locked_interposer(metadata: &Value) -> Result<Option<Locked>, String> {
    let found: Vec<&Value> = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|package| package["name"] == "snare-interpose")
        .collect();
    let [package] = found.as_slice() else {
        if found.is_empty() {
            return Ok(None);
        }
        let versions: Vec<String> = found
            .iter()
            .map(|package| {
                format!(
                    "{} ({})",
                    package["version"].as_str().unwrap_or("?"),
                    package["source"].as_str().unwrap_or("path")
                )
            })
            .collect();
        return Err(format!(
            "the dependency graph holds more than one snare-interpose: {}; unify the snare \
             dependencies, or pass --shims-dir",
            versions.join(", ")
        ));
    };
    let version = package["version"].as_str().unwrap_or_default().to_string();
    Ok(Some(match package["source"].as_str() {
        None => Locked::Path(PathBuf::from(
            package["manifest_path"].as_str().unwrap_or_default(),
        )),
        Some(source) if source.starts_with("registry+") || source.starts_with("sparse+") => {
            Locked::Registry(version)
        }
        Some(source) => match source.strip_prefix("git+") {
            Some(git) => parse_git(git),
            None => Locked::Registry(version),
        },
    }))
}

/// A `cargo metadata` git source id without its `git+` prefix:
/// `<url>[?tag=..|?branch=..|?rev=..]#<commit>`.
fn parse_git(git: &str) -> Locked {
    let without_commit = git.split_once('#').map_or(git, |(head, _)| head);
    let (url, query) = without_commit
        .split_once('?')
        .unwrap_or((without_commit, ""));
    let reference = query
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some(match key {
                "tag" => GitRef::Tag(value.to_string()),
                "branch" => GitRef::Branch(value.to_string()),
                "rev" => GitRef::Rev(value.to_string()),
                _ => return None,
            })
        })
        .unwrap_or(GitRef::Default);
    Locked::Git {
        url: url.to_string(),
        reference,
    }
}

/// The `shims/` directory of the snare repository holding the `snare-interpose` manifest
/// `manifest` (`<repo>/crates/snare-interpose/Cargo.toml`), if there is one.
fn repository_shims(manifest: &Path) -> Option<PathBuf> {
    let shims = manifest.parent()?.parent()?.parent()?.join("shims");
    shims.is_dir().then_some(shims)
}

/// `path` as a TOML basic string, escaping `\` and `"` (TOML v1.0.0, String, basic strings), so
/// Windows paths survive inside `--config`.
pub(crate) fn toml_string(path: &Path) -> String {
    let escaped = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn with(source: Option<&str>, manifest: &str) -> Value {
        json!({"packages": [
            {"name": "snare-interpose", "version": "3.1.0", "source": source, "manifest_path": manifest},
            {"name": "snare", "version": "3.1.0", "source": source, "manifest_path": manifest},
        ]})
    }

    #[test]
    fn a_registry_interposer_takes_everything_from_its_release_tag() {
        let metadata = with(
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            "/x",
        );
        let source = resolve(&metadata, None, None, "v9.9.9").unwrap();
        assert_eq!(
            source,
            Source::Git {
                url: SNARE_GIT.into(),
                reference: GitRef::Tag("v3.1.0".into()),
                interposer: true,
            }
        );
        let patches = source.interposer_patches();
        assert!(patches.contains(&format!("patch.crates-io.snare.git=\"{SNARE_GIT}\"")));
        assert!(patches.contains(&"patch.crates-io.snare-interpose.tag=\"v3.1.0\"".to_string()));
    }

    #[test]
    fn a_git_interposer_keeps_its_reference() {
        let metadata = with(
            Some("git+https://example.com/snare?branch=dev#0123abcd"),
            "/x",
        );
        let source = resolve(&metadata, None, None, "v9.9.9").unwrap();
        assert_eq!(
            source,
            Source::Git {
                url: "https://example.com/snare".into(),
                reference: GitRef::Branch("dev".into()),
                interposer: false,
            }
        );
        assert!(source.interposer_patches().is_empty());
        assert_eq!(
            source.patch("smol", "smol"),
            vec![
                "patch.crates-io.smol.git=\"https://example.com/snare\"".to_string(),
                "patch.crates-io.smol.branch=\"dev\"".to_string(),
            ]
        );
    }

    #[test]
    fn a_git_interposer_on_the_default_branch_names_no_reference() {
        let metadata = with(Some("git+https://example.com/snare#0123abcd"), "/x");
        let source = resolve(&metadata, None, None, "v9.9.9").unwrap();
        assert_eq!(source.patch("sc", "sc").len(), 1);
    }

    #[test]
    fn a_path_interposer_uses_its_checkouts_shims() {
        let root = std::env::temp_dir().join(format!("cargo-snare-src-{}", std::process::id()));
        std::fs::create_dir_all(root.join("crates/snare-interpose")).unwrap();
        std::fs::create_dir_all(root.join("shims")).unwrap();
        let manifest = root.join("crates/snare-interpose/Cargo.toml");
        let metadata = with(None, manifest.to_str().unwrap());
        let source = resolve(&metadata, None, None, "v9.9.9").unwrap();
        assert_eq!(source, Source::Path(root.join("shims")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_path_interposer_without_shims_is_an_error() {
        let metadata = with(None, "/nowhere/crates/snare-interpose/Cargo.toml");
        assert!(resolve(&metadata, None, None, "v9.9.9").is_err());
    }

    #[test]
    fn no_interposer_falls_back_to_this_release() {
        let metadata = json!({"packages": []});
        let source = resolve(&metadata, None, None, "v9.9.9").unwrap();
        assert_eq!(
            source,
            Source::Git {
                url: SNARE_GIT.into(),
                reference: GitRef::Tag("v9.9.9".into()),
                interposer: false,
            }
        );
    }

    #[test]
    fn explicit_choices_win() {
        let metadata = with(
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            "/x",
        );
        assert_eq!(
            resolve(&metadata, Some(Path::new("/s")), None, "v9.9.9").unwrap(),
            Source::Path("/s".into())
        );
        assert_eq!(
            resolve(&metadata, None, Some("abc"), "v9.9.9").unwrap(),
            Source::Git {
                url: SNARE_GIT.into(),
                reference: GitRef::Rev("abc".into()),
                interposer: true,
            }
        );
    }

    #[test]
    fn a_release_tag_names_its_version() {
        let tagged = |tag: &str| Source::Git {
            url: SNARE_GIT.into(),
            reference: GitRef::Tag(tag.into()),
            interposer: true,
        };
        assert_eq!(tagged("v3.0.1").release(), Some((3, 0, 1)));
        assert_eq!(tagged("release-3").release(), None);
        assert_eq!(Source::Path("/s".into()).release(), None);
    }

    #[test]
    fn two_interposers_are_an_error() {
        let metadata = json!({"packages": [
            {"name": "snare-interpose", "version": "3.0.1", "source": "registry+x", "manifest_path": "/a"},
            {"name": "snare-interpose", "version": "3.1.0", "source": "registry+x", "manifest_path": "/b"},
        ]});
        assert!(resolve(&metadata, None, None, "v9.9.9").is_err());
    }
}
