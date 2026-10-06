//! `cargo snare --init`: prepares a package's manifest for snare tests.
//!
//! snare refuses to compile without `--cfg snare`, so the package takes it only under
//! `[target.'cfg(snare)'.dev-dependencies]`: plain `cargo test` never builds it, and `cargo snare
//! test` (which sets the cfg) does. Cargo evaluates `cfg(...)` target tables against the flags in
//! `RUSTFLAGS` ([The Cargo Book: Platform specific dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies)).
//! The `check-cfg` lint entry declares the cfg so `#[cfg(snare)]` does not warn
//! ([The Cargo Book: lints](https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section),
//! [rustc book: Cargo Specifics](https://doc.rust-lang.org/rustc/check-cfg/cargo-specifics.html)).

use std::path::{Path, PathBuf};
use std::process::Command;

use toml_edit::{Array, DocumentMut, InlineTable, Item, Key, Table, Value};

/// The version requirement written for snare: this binary's major version, whose snare has the
/// `cfg(snare)` check and the prelude.
const SNARE_REQ: &str = env!("CARGO_PKG_VERSION_MAJOR");

/// Edits the package manifest at `manifest` (or the one `cargo locate-project` finds) and, when
/// its lints come from the workspace, the workspace root manifest. Returns the exit code.
pub(crate) fn run(manifest: Option<PathBuf>) -> i32 {
    match init(manifest) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cargo-snare: {e}");
            1
        }
    }
}

fn init(manifest: Option<PathBuf>) -> Result<(), String> {
    let manifest = match manifest {
        Some(path) => path,
        None => locate_manifest()?,
    };
    let mut doc = read(&manifest)?;
    if !doc.contains_key("package") {
        return Err(format!(
            "{} has no [package]; run in a member's directory or pass --manifest-path",
            manifest.display()
        ));
    }

    let mut notes = gate_dev_dependency(&mut doc)?;
    let inherits_lints = doc
        .get("lints")
        .and_then(|lints| lints.get("workspace"))
        .and_then(Item::as_bool)
        .unwrap_or(false);
    if inherits_lints {
        let root = workspace_manifest(&manifest)?;
        let mut root_doc = read(&root)?;
        let lints = table_at(&mut root_doc, &["workspace", "lints", "rust"])?;
        if declare_cfg(lints)? {
            write(&root, &root_doc)?;
            notes.push(format!(
                "declared cfg(snare) in [workspace.lints.rust] of {}",
                root.display()
            ));
        }
    } else if declare_cfg(table_at(&mut doc, &["lints", "rust"])?)? {
        notes.push("declared cfg(snare) in [lints.rust]".into());
    }

    write(&manifest, &doc)?;
    if notes.is_empty() {
        println!("cargo-snare: {} is already set up", manifest.display());
    }
    for note in notes {
        println!("cargo-snare: {note}");
    }
    Ok(())
}

/// Moves every snare dev-dependency under a target table whose cfg requires `snare`, combining
/// it with the cfg of the table it was in, or adds `snare = "<major>"` under
/// `cfg(snare)` if there is none. A version requirement is raised to [`SNARE_REQ`].
fn gate_dev_dependency(doc: &mut DocumentMut) -> Result<Vec<String>, String> {
    let mut found: Vec<(Option<String>, Item)> = Vec::new();
    if let Some(deps) = doc
        .get_mut("dev-dependencies")
        .and_then(Item::as_table_like_mut)
        && let Some(dep) = deps.remove("snare")
    {
        found.push((None, dep));
    }
    if let Some(targets) = doc.get_mut("target").and_then(Item::as_table_like_mut) {
        for (key, target) in targets.iter_mut() {
            if gated(key.get()) {
                continue;
            }
            if let Some(deps) = target
                .get_mut("dev-dependencies")
                .and_then(Item::as_table_like_mut)
                && let Some(dep) = deps.remove("snare")
            {
                found.push((Some(key.get().to_owned()), dep));
            }
        }
    }
    prune_empty(doc);

    let already = doc
        .get("target")
        .and_then(Item::as_table_like)
        .is_some_and(|targets| {
            targets.iter().any(|(key, target)| {
                gated(key)
                    && target
                        .get("dev-dependencies")
                        .and_then(|deps| deps.get("snare"))
                        .is_some()
            })
        });
    if found.is_empty() {
        if already {
            return Ok(Vec::new());
        }
        found.push((None, Item::Value(SNARE_REQ.into())));
    }

    let mut notes = Vec::new();
    for (from, mut dep) in found {
        raise_version(&mut dep);
        let cfg = match &from {
            None => "cfg(snare)".to_string(),
            Some(key) => {
                let inner = key
                    .strip_prefix("cfg(")
                    .and_then(|rest| rest.strip_suffix(')'))
                    .ok_or_else(|| {
                        format!(
                            "snare is a dev-dependency of target `{key}`, which is not a cfg(...) \
                             expression; move it under a cfg(all(snare, ...)) table by hand"
                        )
                    })?;
                format!("cfg(all(snare, {inner}))")
            }
        };
        let deps = table_at(doc, &["target", &cfg, "dev-dependencies"])?;
        deps.insert("snare", dep);
        notes.push(match from {
            None => format!("snare is a dev-dependency under [target.'{cfg}']"),
            Some(key) => format!("moved snare from [target.'{key}'] to [target.'{cfg}']"),
        });
    }
    Ok(notes)
}

/// Whether a `[target.<key>]` cfg already requires `snare`: `cfg(snare)` or an `all(...)` that
/// lists it.
fn gated(key: &str) -> bool {
    let compact: String = key.chars().filter(|c| !c.is_whitespace()).collect();
    compact == "cfg(snare)" || compact.starts_with("cfg(all(snare,")
}

/// Sets the version requirement of a dependency to [`SNARE_REQ`] when it has one.
fn raise_version(dep: &mut Item) {
    match dep {
        Item::Value(Value::String(_)) => *dep = Item::Value(SNARE_REQ.into()),
        Item::Value(Value::InlineTable(table)) if table.contains_key("version") => {
            table.insert("version", SNARE_REQ.into());
        }
        Item::Table(table) if table.contains_key("version") => {
            table.insert("version", Item::Value(SNARE_REQ.into()));
        }
        _ => {}
    }
}

/// Drops dev-dependency tables and target tables left empty by a move.
fn prune_empty(doc: &mut DocumentMut) {
    if doc
        .get("dev-dependencies")
        .and_then(Item::as_table_like)
        .is_some_and(|deps| deps.is_empty())
    {
        doc.remove("dev-dependencies");
    }
    let Some(targets) = doc.get_mut("target").and_then(Item::as_table_like_mut) else {
        return;
    };
    let mut empty = Vec::new();
    for (key, target) in targets.iter_mut() {
        let Some(target) = target.as_table_like_mut() else {
            continue;
        };
        if target
            .get("dev-dependencies")
            .and_then(Item::as_table_like)
            .is_some_and(|deps| deps.is_empty())
        {
            target.remove("dev-dependencies");
        }
        if target.is_empty() {
            empty.push(key.get().to_owned());
        }
    }
    for key in empty {
        targets.remove(&key);
    }
}

/// Adds `'cfg(snare)'` to `unexpected_cfgs`'s `check-cfg` list in a `[lints.rust]` table,
/// turning a bare level into `{ level = ..., check-cfg = [...] }`. Returns whether it changed.
fn declare_cfg(lints: &mut Table) -> Result<bool, String> {
    let entry: Value = "'cfg(snare)'".parse().expect("a TOML literal string");
    let lint = match lints.get_mut("unexpected_cfgs") {
        None => {
            let mut table = InlineTable::new();
            table.insert("level", "warn".into());
            table.insert("check-cfg", Value::Array(Array::from_iter([entry])));
            lints.insert("unexpected_cfgs", Item::Value(Value::InlineTable(table)));
            return Ok(true);
        }
        Some(lint) => lint,
    };
    if let Some(level) = lint.as_str().map(str::to_owned) {
        let mut table = InlineTable::new();
        table.insert("level", level.into());
        table.insert("check-cfg", Value::Array(Array::from_iter([entry])));
        *lint = Item::Value(Value::InlineTable(table));
        return Ok(true);
    }
    let table = lint
        .as_table_like_mut()
        .ok_or("[lints.rust] unexpected_cfgs is neither a level nor a table")?;
    let list = table
        .entry("check-cfg")
        .or_insert(Item::Value(Value::Array(Array::new())))
        .as_array_mut()
        .ok_or("unexpected_cfgs.check-cfg is not an array")?;
    let present = list.iter().any(|v| {
        v.as_str().is_some_and(|s| {
            s.chars()
                .filter(|c| !c.is_whitespace())
                .eq("cfg(snare)".chars())
        })
    });
    if !present {
        list.push_formatted(entry);
    }
    Ok(!present)
}

/// The table at `path`, creating missing tables as standard (non-inline) ones; dotted keys in
/// `target` stay single quoted keys.
fn table_at<'a>(doc: &'a mut DocumentMut, path: &[&str]) -> Result<&'a mut Table, String> {
    let mut table = doc.as_table_mut();
    for (i, key) in path.iter().enumerate() {
        let item = table.entry_format(&literal_key(key)).or_insert_with(|| {
            let mut new = Table::new();
            new.set_implicit(i + 1 < path.len());
            Item::Table(new)
        });
        if let Some(inline) = item.as_inline_table().cloned() {
            *item = Item::Table(inline.into_table());
        }
        table = item
            .as_table_mut()
            .ok_or_else(|| format!("`{}` is not a table", path[..=i].join(".")))?;
    }
    Ok(table)
}

/// `key` as written in a header: bare when TOML allows it, otherwise a literal string, as cargo's
/// documentation writes `[target.'cfg(...)'.dependencies]`.
fn literal_key(key: &str) -> Key {
    let bare = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare || key.contains('\'') {
        return Key::new(key);
    }
    format!("'{key}'").parse().unwrap_or_else(|_| Key::new(key))
}

fn locate_manifest() -> Result<PathBuf, String> {
    let out = cargo_stdout(&["locate-project", "--message-format", "plain"])?;
    Ok(PathBuf::from(out.trim()))
}

/// The workspace root manifest of the package at `manifest`.
fn workspace_manifest(manifest: &Path) -> Result<PathBuf, String> {
    let out = cargo_stdout(&[
        "locate-project",
        "--workspace",
        "--message-format",
        "plain",
        "--manifest-path",
        &manifest.display().to_string(),
    ])?;
    Ok(PathBuf::from(out.trim()))
}

fn cargo_stdout(args: &[&str]) -> Result<String, String> {
    let output = Command::new("cargo")
        .args(args)
        .output()
        .map_err(|e| format!("could not run cargo: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`cargo {}` failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn read(path: &Path) -> Result<DocumentMut, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?
        .parse()
        .map_err(|e| format!("parsing {}: {e}", path.display()))
}

fn write(path: &Path, doc: &DocumentMut) -> Result<(), String> {
    std::fs::write(path, doc.to_string()).map_err(|e| format!("writing {}: {e}", path.display()))
}
