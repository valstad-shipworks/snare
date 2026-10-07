//! Which of `shims/` to patch in, and which parallel-only behaviour to turn on.
//!
//! A default shim is patched whenever its crate is in the dependency graph: without it the crate
//! escapes the interposer or replays differently. A parallel shim only gives each sim its own
//! copy of a crate's process-wide state (a reactor, an executor, a thread pool) so that sims using
//! it can run at the same time; without it they still work, taking turns. Parallel shims are
//! patched only when asked for, by `--parallel` or by `parallel = [...]` under
//! `[workspace.metadata.snare]` or a member's `[package.metadata.snare]`.
//!
//! rayon-core's shim is both: its per-registry steal seeding is default, and its per-sim global
//! pool is compiled in only under `--cfg snare_parallel_rayon`, which `--parallel rayon` adds.

use std::collections::BTreeSet;

use serde_json::Value;

/// Why a shim exists, which decides whether it is patched by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// The crate escapes the interposer, or replays differently, without it.
    Default,
    /// Only lets concurrent sims each keep their own copy of the crate's process-wide state.
    Parallel,
}

/// One drop-in replacement under `shims/`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Shim {
    /// The crates.io package it replaces.
    pub(crate) krate: &'static str,
    /// Its directory under `shims/`.
    pub(crate) dir: &'static str,
    /// The semver-compatible release line it replaces: `0.12` matches 0.12.x, `2` matches 2.x.
    pub(crate) line: &'static str,
    pub(crate) need: Need,
}

impl Shim {
    const fn new(krate: &'static str, dir: &'static str, line: &'static str, need: Need) -> Self {
        Shim {
            krate,
            dir,
            line,
            need,
        }
    }

    /// Whether `version` of the crate is one this shim can stand in for.
    pub(crate) fn replaces(&self, version: &str) -> bool {
        version
            .strip_prefix(self.line)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    }

    /// The `[patch.crates-io]` key: the crate's name, or for a crate with a shim per release
    /// line, a name of its own (`quanta_0_12`) that `package` maps back to the crate.
    pub(crate) fn patch_key(&self) -> String {
        if self.aliased() {
            self.dir.replace(['-', '.'], "_")
        } else {
            self.krate.to_string()
        }
    }

    /// Whether the patch needs a `package` and a `version` to pick this shim out of several of
    /// the same crate.
    pub(crate) fn aliased(&self) -> bool {
        self.dir != self.krate
    }

    /// How dry runs and messages name it.
    pub(crate) fn label(&self) -> String {
        if self.aliased() {
            format!("{} {}", self.krate, self.line)
        } else {
            self.krate.to_string()
        }
    }
}

/// Every shim, in the order they are patched.
pub(crate) const SHIMS: [Shim; 14] = [
    Shim::new("io-uring", "io-uring", "0.7", Need::Default),
    Shim::new("xsk-rs", "xsk-rs", "0.8", Need::Default),
    Shim::new("sc", "sc", "0.2", Need::Default),
    Shim::new("syscalls", "syscalls", "0.8", Need::Default),
    Shim::new("quanta", "quanta-0.12", "0.12", Need::Default),
    Shim::new("quanta", "quanta-0.13", "0.13", Need::Default),
    Shim::new("minstant", "minstant", "0.1", Need::Default),
    Shim::new("fastant", "fastant", "0.1", Need::Default),
    Shim::new("fastrand", "fastrand", "2", Need::Default),
    Shim::new("rayon-core", "rayon-core", "1", Need::Default),
    Shim::new("async-io", "async-io", "2", Need::Parallel),
    Shim::new(
        "async-global-executor",
        "async-global-executor",
        "2",
        Need::Parallel,
    ),
    Shim::new("blocking", "blocking", "1", Need::Parallel),
    Shim::new("smol", "smol", "2", Need::Parallel),
];

/// Crates whose per-sim mode is a cfg read by their default shim rather than a shim of its own.
pub(crate) const PARALLEL_CFGS: [(&str, &str); 1] = [("rayon-core", "snare_parallel_rayon")];

/// The names `--parallel` and `parallel = [...]` accept, each with the crates it turns per-sim
/// state on for. A runtime brings every crate its global state lives in.
pub(crate) const PARALLEL_NAMES: [(&str, &[&str]); 9] = [
    (
        "all",
        &[
            "async-io",
            "async-global-executor",
            "blocking",
            "smol",
            "rayon-core",
        ],
    ),
    (
        "async-std",
        &["async-io", "async-global-executor", "blocking"],
    ),
    ("smol", &["async-io", "blocking", "smol"]),
    ("rayon", &["rayon-core"]),
    ("rayon-core", &["rayon-core"]),
    ("async-io", &["async-io"]),
    ("async-global-executor", &["async-global-executor"]),
    ("blocking", &["blocking"]),
    ("none", &[]),
];

/// The crates selected for per-sim state, and where the selection came from.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Parallel {
    pub(crate) crates: BTreeSet<&'static str>,
    pub(crate) source: String,
}

/// Expands `--parallel`/`parallel = [...]` names (each may itself be comma-separated) into the
/// crates they select. `Err` names the first unknown one.
pub(crate) fn expand(names: &[String]) -> Result<BTreeSet<&'static str>, String> {
    let mut crates = BTreeSet::new();
    for name in names.iter().flat_map(|n| n.split(',')).map(str::trim) {
        if name.is_empty() {
            continue;
        }
        let Some((_, selected)) = PARALLEL_NAMES.iter().find(|(known, _)| *known == name) else {
            let known: Vec<&str> = PARALLEL_NAMES.iter().map(|(known, _)| *known).collect();
            return Err(format!(
                "unknown parallel name `{name}`; expected one of {}",
                known.join(", ")
            ));
        };
        crates.extend(selected.iter().copied());
    }
    Ok(crates)
}

/// The selection made in `cargo metadata`'s output: the union of `parallel` under
/// `[workspace.metadata.snare]` and every workspace member's `[package.metadata.snare]`.
pub(crate) fn configured(metadata: &Value) -> Result<Parallel, String> {
    let mut crates = BTreeSet::new();
    let mut sources = Vec::new();
    let mut take = |snare: Option<&Value>, from: String| -> Result<(), String> {
        let Some(list) = snare.and_then(|snare| snare.get("parallel")) else {
            return Ok(());
        };
        let names = list
            .as_array()
            .and_then(|list| {
                list.iter()
                    .map(|name| name.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| format!("`parallel` in {from} must be an array of strings"))?;
        crates.extend(expand(&names).map_err(|e| format!("{from}: {e}"))?);
        sources.push(from);
        Ok(())
    };

    take(
        metadata.pointer("/metadata/snare"),
        "[workspace.metadata.snare]".to_string(),
    )?;
    let members: Vec<&str> = metadata["workspace_members"]
        .as_array()
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let is_member = package["id"]
            .as_str()
            .is_some_and(|id| members.contains(&id));
        if is_member {
            let name = package["name"].as_str().unwrap_or("?");
            take(
                package.pointer("/metadata/snare"),
                format!("[package.metadata.snare] of {name}"),
            )?;
        }
    }

    Ok(Parallel {
        crates,
        source: sources.join(", "),
    })
}

/// Every `(name, version)` package in `cargo metadata`'s output.
pub(crate) fn packages(metadata: &Value) -> Vec<(String, String)> {
    metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| {
            Some((
                package["name"].as_str()?.to_string(),
                package["version"].as_str()?.to_string(),
            ))
        })
        .collect()
}

/// The shims to patch, from those `present`: each default shim, and each parallel shim whose crate
/// `parallel` selects; with `all`, regardless of the graph, else only those replacing a version
/// in `graph`. Patching a crate the graph lacks is harmless, but cargo warns that the patch was
/// not used.
pub(crate) fn select<'a>(
    present: impl IntoIterator<Item = &'a Shim>,
    graph: &[(String, String)],
    parallel: &BTreeSet<&str>,
    all: bool,
) -> Vec<&'a Shim> {
    present
        .into_iter()
        .filter(|shim| shim.need == Need::Default || parallel.contains(shim.krate))
        .filter(|shim| {
            all || graph
                .iter()
                .any(|(name, version)| name == shim.krate && shim.replaces(version))
        })
        .collect()
}

/// The `--cfg` names that turn on the selected per-sim modes of the shims being patched.
pub(crate) fn cfgs(patched: &[&Shim], parallel: &BTreeSet<&str>) -> Vec<&'static str> {
    PARALLEL_CFGS
        .iter()
        .filter(|(krate, _)| {
            parallel.contains(krate) && patched.iter().any(|shim| shim.krate == *krate)
        })
        .map(|(_, cfg)| *cfg)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    fn set(list: &[&'static str]) -> BTreeSet<&'static str> {
        list.iter().copied().collect()
    }

    fn graph(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    fn dirs(shims: &[&Shim]) -> Vec<&'static str> {
        shims.iter().map(|shim| shim.dir).collect()
    }

    #[test]
    fn runtime_names_bring_their_crates() {
        assert_eq!(
            expand(&names(&["async-std"])).unwrap(),
            set(&["async-io", "async-global-executor", "blocking"])
        );
        assert_eq!(
            expand(&names(&["smol,rayon"])).unwrap(),
            set(&["async-io", "blocking", "smol", "rayon-core"])
        );
        assert_eq!(
            expand(&names(&["blocking", " async-io "])).unwrap(),
            set(&["async-io", "blocking"])
        );
        assert_eq!(expand(&names(&["none"])).unwrap(), set(&[]));
    }

    #[test]
    fn all_selects_every_parallel_crate() {
        let all = expand(&names(&["all"])).unwrap();
        for shim in SHIMS.iter().filter(|shim| shim.need == Need::Parallel) {
            assert!(all.contains(shim.krate), "{} missing", shim.krate);
        }
        for (krate, _) in PARALLEL_CFGS {
            assert!(all.contains(krate), "{krate} missing");
        }
    }

    #[test]
    fn every_parallel_name_selects_a_parallel_crate() {
        let parallel: BTreeSet<&str> = SHIMS
            .iter()
            .filter(|shim| shim.need == Need::Parallel)
            .map(|shim| shim.krate)
            .chain(PARALLEL_CFGS.iter().map(|(krate, _)| *krate))
            .collect();
        for (name, crates) in PARALLEL_NAMES {
            for krate in crates {
                assert!(parallel.contains(krate), "{name} selects {krate}");
            }
        }
    }

    #[test]
    fn unknown_names_are_rejected() {
        let err = expand(&names(&["smol", "tokio"])).unwrap_err();
        assert!(err.contains("`tokio`"), "{err}");
        assert!(err.contains("async-std"), "{err}");
    }

    #[test]
    fn release_lines_match_semver_compatible_versions() {
        let quanta_012 = &SHIMS[4];
        assert!(quanta_012.replaces("0.12.6"));
        assert!(quanta_012.replaces("0.12.0-rc.1"));
        assert!(!quanta_012.replaces("0.13.0"));
        assert!(!quanta_012.replaces("0.120.0"));
        let fastrand = SHIMS.iter().find(|s| s.krate == "fastrand").unwrap();
        assert!(fastrand.replaces("2.3.0"));
        assert!(!fastrand.replaces("1.9.0"));
    }

    #[test]
    fn crates_with_a_shim_per_line_get_their_own_patch_keys() {
        let keys: Vec<String> = SHIMS.iter().map(Shim::patch_key).collect();
        assert!(keys.contains(&"quanta_0_12".to_string()));
        assert!(keys.contains(&"quanta_0_13".to_string()));
        assert!(keys.contains(&"rayon-core".to_string()));
        let unique: BTreeSet<&String> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
        assert_eq!(SHIMS[4].label(), "quanta 0.12");
        assert_eq!(SHIMS[9].label(), "rayon-core");
    }

    #[test]
    fn default_shims_follow_the_graph_and_parallel_ones_need_opting_in() {
        let g = graph(&[
            ("quanta", "0.12.6"),
            ("quanta", "0.13.0"),
            ("fastrand", "1.9.0"),
            ("rayon-core", "1.12.1"),
            ("async-io", "2.4.0"),
            ("blocking", "1.6.1"),
            ("smol", "2.0.2"),
        ]);
        assert_eq!(
            dirs(&select(&SHIMS, &g, &set(&[]), false)),
            ["quanta-0.12", "quanta-0.13", "rayon-core"]
        );
        assert_eq!(
            dirs(&select(
                &SHIMS,
                &g,
                &set(&["async-io", "blocking", "smol"]),
                false
            )),
            [
                "quanta-0.12",
                "quanta-0.13",
                "rayon-core",
                "async-io",
                "blocking",
                "smol"
            ]
        );
        assert_eq!(
            dirs(&select(&SHIMS, &g, &set(&["async-global-executor"]), false)),
            ["quanta-0.12", "quanta-0.13", "rayon-core"]
        );
    }

    #[test]
    fn all_shims_ignores_the_graph_but_not_the_opt_in() {
        let every_default = SHIMS.iter().filter(|s| s.need == Need::Default).count();
        assert_eq!(select(&SHIMS, &[], &set(&[]), true).len(), every_default);
        let with_smol = select(&SHIMS, &[], &set(&["smol"]), true);
        assert_eq!(with_smol.len(), every_default + 1);
        assert_eq!(with_smol.last().unwrap().krate, "smol");
    }

    #[test]
    fn only_present_shims_are_selected() {
        let g = graph(&[("quanta", "0.13.0"), ("smol", "2.0.2")]);
        let present: Vec<&Shim> = SHIMS.iter().filter(|s| s.dir != "quanta-0.13").collect();
        assert!(select(present, &g, &set(&[]), false).is_empty());
    }

    #[test]
    fn the_rayon_cfg_needs_both_the_opt_in_and_the_patch() {
        let rayon = select(
            &SHIMS,
            &graph(&[("rayon-core", "1.13.0")]),
            &set(&[]),
            false,
        );
        assert_eq!(
            cfgs(&rayon, &set(&["rayon-core"])),
            ["snare_parallel_rayon"]
        );
        assert!(cfgs(&rayon, &set(&[])).is_empty());
        assert!(cfgs(&[], &set(&["rayon-core"])).is_empty());
    }

    #[test]
    fn configuration_unions_workspace_and_member_metadata() {
        let metadata = serde_json::json!({
            "metadata": { "snare": { "parallel": ["rayon"] } },
            "workspace_members": ["path+file:///w/a#0.1.0", "path+file:///w/b#0.1.0"],
            "packages": [
                { "id": "path+file:///w/a#0.1.0", "name": "a", "version": "0.1.0",
                  "metadata": { "snare": { "parallel": ["smol"] } } },
                { "id": "path+file:///w/b#0.1.0", "name": "b", "version": "0.1.0",
                  "metadata": null },
                { "id": "registry+https://github.com/rust-lang/crates.io-index#dep@1.0.0",
                  "name": "dep", "version": "1.0.0",
                  "metadata": { "snare": { "parallel": ["async-std"] } } }
            ]
        });
        let parallel = configured(&metadata).unwrap();
        assert_eq!(
            parallel.crates,
            set(&["async-io", "blocking", "smol", "rayon-core"])
        );
        assert_eq!(
            parallel.source,
            "[workspace.metadata.snare], [package.metadata.snare] of a"
        );
        assert_eq!(
            packages(&metadata)[2],
            ("dep".to_string(), "1.0.0".to_string())
        );
    }

    #[test]
    fn bad_configuration_is_reported() {
        let not_a_list = serde_json::json!({ "metadata": { "snare": { "parallel": "smol" } } });
        assert!(
            configured(&not_a_list)
                .unwrap_err()
                .contains("array of strings")
        );
        let unknown = serde_json::json!({ "metadata": { "snare": { "parallel": ["tokio"] } } });
        let err = configured(&unknown).unwrap_err();
        assert!(
            err.starts_with("[workspace.metadata.snare]: unknown"),
            "{err}"
        );
        let empty = serde_json::json!({ "packages": [] });
        assert_eq!(configured(&empty).unwrap(), Parallel::default());
    }
}
