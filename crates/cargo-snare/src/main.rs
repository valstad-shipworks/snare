//! `cargo snare` — build and run a crate's `#[cfg(snare)]` tests under the snare interposer.
//!
//! Cargo invokes an external subcommand `cargo snare <args>` as `cargo-snare snare <args>`: "the
//! second argument will be the subcommand name itself", so `argv[1]` is dropped before parsing
//! ([The Cargo Book: External tools, Custom subcommands](https://doc.rust-lang.org/cargo/reference/external-tools.html#custom-subcommands)).
//!
//! `cargo snare --init` prepares a package's manifest: snare as a dev-dependency only under
//! `cfg(snare)`, and the cfg declared to the `unexpected_cfgs` lint.
//!
//! `cargo snare test` runs `cargo test` with three changes: `--cfg snare` (so the crate's
//! `#[cfg(snare)]` tests and helpers compile), `--cfg rustix_use_libc` (so rustix calls libc,
//! whose imports snare interposes, instead of issuing raw syscalls), and a
//! `--config patch.crates-io.<shim>…` for every drop-in shim the dependency graph needs: crates
//! that would otherwise reach the kernel or the CPU's counters where the interposer cannot see
//! them, or seed from process-wide state a sim cannot replay (see `shims/README.md`). Shims that
//! only give each sim its own copy of a crate's process-wide state are patched only when
//! `--parallel` or the workspace's `[*.metadata.snare] parallel` asks for them (see [`shims`]).
//! The shims come from the snare repository at the tag matching this binary's version, or from a
//! local `--shims-dir`.

mod init;
mod shims;

use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use clap::{Args, Parser, Subcommand};
use serde_json::Value;

use shims::{Parallel, SHIMS, Shim};

/// The repository holding `shims/`. Cargo finds a git dependency's package by name anywhere in
/// the repository, so each shim resolves to its subdirectory.
const SHIMS_GIT: &str = "https://github.com/valstad-shipworks/snare";

/// The release tag of this binary, whose `shims/` match the interposer it was released with.
const SHIMS_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Appended to `RUSTFLAGS`. `rustix_use_libc` is the cfg rustix's build script reads to select
/// its libc backend (rustix README, "set the RUSTFLAGS environment variable to
/// --cfg=rustix_use_libc"; rustix build.rs `CARGO_CFG_RUSTIX_USE_LIBC`). The `--check-cfg`
/// entries declare these cfgs and the parallel ones of [`shims::PARALLEL_CFGS`] so `unexpected_cfgs`
/// does not warn about them
/// ([The rustc book: Checking conditional configurations](https://doc.rust-lang.org/rustc/check-cfg.html)).
const SNARE_RUSTFLAGS: [&str; 7] = [
    "--cfg",
    "snare",
    "--cfg",
    "rustix_use_libc",
    "--check-cfg=cfg(snare)",
    "--check-cfg=cfg(rustix_use_libc)",
    "--check-cfg=cfg(snare_parallel_rayon)",
];

/// The command line after the `snare` argument is dropped.
#[derive(Parser)]
#[command(
    name = "cargo-snare",
    bin_name = "cargo snare",
    version,
    about = "Run a crate's #[cfg(snare)] tests under the snare interposer",
    args_conflicts_with_subcommands = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Put the package's snare dev-dependency under `[target.'cfg(snare)'.dev-dependencies]`
    /// (adding it if missing) and declare `cfg(snare)` in its `[lints.rust]`.
    #[arg(long)]
    init: bool,

    /// The package manifest `--init` edits, instead of the one cargo finds from the current
    /// directory.
    #[arg(long, value_name = "PATH", requires = "init")]
    manifest_path: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

/// `cargo snare`'s subcommands.
#[derive(Subcommand)]
enum Cmd {
    /// Build and run the crate's tests with `--cfg snare` and the syscall shims patched in.
    Test(TestArgs),
}

/// Options of `cargo snare test`.
#[derive(Args)]
struct TestArgs {
    /// Directory holding the drop-in shims (the snare repository's `shims/`), used instead of the
    /// snare repository's tagged copy.
    #[arg(long, value_name = "DIR")]
    shims_dir: Option<PathBuf>,

    /// Git ref (tag, branch or commit) of the snare repository to take the shims from.
    #[arg(long, value_name = "REF", default_value = SHIMS_TAG, conflicts_with = "shims_dir")]
    shims_rev: String,

    /// Patch every default shim, and every parallel shim `--parallel` selects, even ones whose
    /// crate is not in the dependency graph. Never selects a parallel shim by itself.
    #[arg(long)]
    all_shims: bool,

    /// Give each sim its own copy of these crates' process-wide state, so sims using them can
    /// run concurrently instead of taking turns: `async-std`, `smol`, `rayon`, `async-io`,
    /// `async-global-executor`, `blocking`, `all`, or `none`. Comma-separated or repeated;
    /// replaces `parallel = [...]` from `[workspace.metadata.snare]` and
    /// `[package.metadata.snare]`.
    #[arg(long, value_name = "NAMES", value_delimiter = ',')]
    parallel: Option<Vec<String>>,

    /// Print the assembled cargo invocation instead of running it.
    #[arg(long)]
    dry_run: bool,

    /// Arguments forwarded verbatim to `cargo test` (e.g. `--test foo -- --nocapture`).
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CARGO_ARGS"
    )]
    cargo_args: Vec<String>,
}

/// Drops the `snare` argument cargo inserts, parses the rest and exits with the child cargo's
/// status. Run directly as `cargo-snare test …`, there is no `snare` to drop.
fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("snare") {
        args.remove(1);
    }
    let cli = Cli::parse_from(&args);
    match cli.cmd {
        Some(Cmd::Test(mut test)) => {
            restore_separator(&args, &mut test.cargo_args);
            exit(run_test(test))
        }
        None => exit(init::run(cli.manifest_path)),
    }
}

/// Puts back the `--` clap takes as the end of `cargo snare test`'s own options when it comes
/// right before the forwarded arguments, so `cargo snare test -- --nocapture` passes
/// `-- --nocapture` to `cargo test` rather than `--nocapture`. The forwarded arguments are always
/// the tail of the command line.
fn restore_separator(raw: &[String], cargo_args: &mut Vec<String>) {
    let Some(before) = raw.len().checked_sub(cargo_args.len() + 1) else {
        return;
    };
    if before > 0 && raw[before] == "--" {
        cargo_args.insert(0, "--".to_string());
    }
}

/// Runs (or, with `--dry-run`, prints) `cargo test` with the shims patched in and the snare cfgs
/// appended to `RUSTFLAGS`, returning the exit code to use: cargo's own, or 1 if it could not be
/// started or died by a signal, or the selection could not be made.
///
/// Any `RUSTFLAGS` already in the environment is kept and extended. Cargo takes extra flags
/// from the first of `CARGO_ENCODED_RUSTFLAGS`, `RUSTFLAGS`, `target.*.rustflags` and
/// `build.rustflags` that is set
/// ([The Cargo Book: Configuration, build.rustflags](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags)),
/// so setting `RUSTFLAGS` stops rustflags from `.cargo/config.toml` being applied, and a
/// `CARGO_ENCODED_RUSTFLAGS` in the environment would win over it and drop the snare cfgs.
/// The patches go on the command line as `--config`, which takes precedence over config files
/// and accepts `[patch]` tables ([The Cargo Book: Configuration, Command-line overrides and
/// patch](https://doc.rust-lang.org/cargo/reference/config.html#command-line-overrides)).
fn run_test(args: TestArgs) -> i32 {
    let metadata = match cargo_metadata() {
        Ok(metadata) => metadata,
        Err(code) => return code,
    };
    let parallel = match &args.parallel {
        Some(names) => shims::expand(names).map(|crates| Parallel {
            crates,
            source: "--parallel".to_string(),
        }),
        None => shims::configured(&metadata),
    };
    let parallel = match parallel {
        Ok(parallel) => parallel,
        Err(e) => {
            eprintln!("cargo-snare: {e}");
            return 1;
        }
    };

    let present: Vec<&Shim> = SHIMS
        .iter()
        .filter(|shim| {
            args.shims_dir
                .as_deref()
                .is_none_or(|dir| dir.join(shim.dir).join("Cargo.toml").is_file())
        })
        .collect();
    if present.is_empty() {
        eprintln!(
            "cargo-snare: no shims found under {}",
            args.shims_dir.as_deref().unwrap_or(Path::new("")).display()
        );
        return 1;
    }
    let graph = shims::packages(&metadata);
    let patches = shims::select(present, &graph, &parallel.crates, args.all_shims);
    let cfgs = shims::cfgs(&patches, &parallel.crates);

    let mut cmd = Command::new("cargo");
    cmd.arg("test");
    for shim in &patches {
        let key = shim.patch_key();
        let mut set = |field: &str, value: String| {
            cmd.arg("--config")
                .arg(format!("patch.crates-io.{key}.{field}={value}"));
        };
        match &args.shims_dir {
            Some(dir) => set("path", toml_string(&dir.join(shim.dir))),
            None => {
                set("git", format!("\"{SHIMS_GIT}\""));
                set("rev", format!("\"{}\"", args.shims_rev));
            }
        }
        if shim.aliased() {
            set("package", format!("\"{}\"", shim.krate));
            set("version", format!("\"{}\"", shim.line));
        }
    }
    cmd.args(&args.cargo_args);

    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let parallel_flags = cfgs.iter().flat_map(|cfg| ["--cfg", cfg]);
    for flag in SNARE_RUSTFLAGS.into_iter().chain(parallel_flags) {
        if !rustflags.is_empty() {
            rustflags.push(' ');
        }
        rustflags.push_str(flag);
    }
    cmd.env("RUSTFLAGS", rustflags);

    if args.dry_run {
        print_invocation(&cmd, &patches, &parallel);
        return 0;
    }

    match cmd.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("cargo-snare: failed to run cargo: {e}");
            1
        }
    }
}

/// `cargo metadata --format-version 1` for the current directory: the resolved packages, whose
/// names and versions decide which shims apply, and the workspace's `metadata` tables
/// ([The Cargo Book: cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)).
/// `Err` carries the exit code if `cargo metadata` fails or cannot be run.
fn cargo_metadata() -> Result<Value, i32> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            eprintln!(
                "cargo-snare: `cargo metadata` failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(output.status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("cargo-snare: could not run `cargo metadata`: {e}");
            return Err(1);
        }
    };
    serde_json::from_slice(&output.stdout).map_err(|e| {
        eprintln!("cargo-snare: could not parse `cargo metadata` output: {e}");
        1
    })
}

/// `path` as a TOML basic string, escaping `\` and `"` (TOML v1.0.0, String, basic strings), so
/// Windows paths survive inside `--config`.
fn toml_string(path: &Path) -> String {
    let escaped = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Prints which shims are patched, which crates get per-sim state, and the command as a shell
/// line, `RUSTFLAGS` included, for `--dry-run`. The arguments are not shell-quoted.
fn print_invocation(cmd: &Command, patches: &[&Shim], parallel: &Parallel) {
    if patches.is_empty() {
        println!("cargo-snare: no shim crates in the dependency graph; none patched");
    } else {
        let labels: Vec<String> = patches.iter().map(|shim| shim.label()).collect();
        println!("cargo-snare: patching {}", labels.join(", "));
    }
    if parallel.crates.is_empty() {
        println!(
            "cargo-snare: parallel: none; sims sharing a runtime's global state take turns \
             (select with --parallel or `parallel = [...]` in [package.metadata.snare])"
        );
    } else {
        let (active, absent): (Vec<&str>, Vec<&str>) = parallel
            .crates
            .iter()
            .partition(|krate| patches.iter().any(|shim| shim.krate == **krate));
        let source = if parallel.source.is_empty() {
            String::new()
        } else {
            format!(" (from {})", parallel.source)
        };
        println!("cargo-snare: parallel: {}{source}", active.join(", "));
        if !absent.is_empty() {
            println!(
                "cargo-snare: parallel: not in the dependency graph: {}",
                absent.join(", ")
            );
        }
    }
    print!("RUSTFLAGS='");
    if let Some(flags) = cmd
        .get_envs()
        .find_map(|(k, v)| (k == "RUSTFLAGS").then_some(v).flatten())
    {
        print!("{}", flags.to_string_lossy());
    }
    print!("' cargo");
    for arg in cmd.get_args() {
        print!(" {}", arg.to_string_lossy());
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Vec<String> {
        let raw: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        let Some(Cmd::Test(mut test)) = Cli::parse_from(&raw).cmd else {
            panic!("not a test command: {line}");
        };
        restore_separator(&raw, &mut test.cargo_args);
        test.cargo_args
    }

    #[test]
    fn a_leading_separator_reaches_cargo() {
        assert_eq!(
            parse("cargo-snare test -- --test-threads=1"),
            ["--", "--test-threads=1"]
        );
        assert_eq!(
            parse("cargo-snare test --parallel smol -- --nocapture"),
            ["--", "--nocapture"]
        );
    }

    #[test]
    fn forwarded_arguments_are_kept_verbatim() {
        assert_eq!(
            parse("cargo-snare test --test foo -- --nocapture"),
            ["--test", "foo", "--", "--nocapture"]
        );
        assert!(parse("cargo-snare test --dry-run").is_empty());
    }

    #[test]
    fn parallel_names_split_and_repeat() {
        let raw: Vec<String> = "cargo-snare test --parallel smol,rayon --parallel async-io"
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let Some(Cmd::Test(test)) = Cli::parse_from(raw).cmd else {
            panic!("not a test command");
        };
        assert_eq!(test.parallel.unwrap(), ["smol", "rayon", "async-io"]);
    }
}
