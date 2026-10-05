//! `cargo snare` — build and run a crate's `#[cfg(snare)]` tests under the snare interposer.
//!
//! Cargo invokes an external subcommand `cargo snare <args>` as `cargo-snare snare <args>`: "the
//! second argument will be the subcommand name itself", so `argv[1]` is dropped before parsing
//! ([The Cargo Book: External tools, Custom subcommands](https://doc.rust-lang.org/cargo/reference/external-tools.html#custom-subcommands)).
//!
//! `cargo snare test` runs `cargo test` with three changes: `--cfg snare` (so the crate's
//! `#[cfg(snare)]` tests and helpers compile), `--cfg rustix_use_libc` (so rustix calls libc,
//! whose imports snare interposes, instead of issuing raw syscalls), and a
//! `--config patch.crates-io.<shim>…` for every drop-in syscall shim the dependency graph uses,
//! replacing crates that would otherwise reach the kernel with inline syscall instructions the
//! interposer cannot see (see `shims/README.md`). The shims come from the snare repository at the
//! tag matching this binary's version, or from a local `--shims-dir`.

use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use clap::{Args, Parser, Subcommand};

/// The repository holding `shims/`. Cargo finds a git dependency's package by name anywhere in
/// the repository, so each shim resolves to its subdirectory.
const SHIMS_GIT: &str = "https://github.com/valstad-shipworks/snare";

/// The release tag of this binary, whose `shims/` match the interposer it was released with.
const SHIMS_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// The crates.io packages `shims/` provides drop-in replacements for; each is a subdirectory of
/// the same name.
const SHIM_CRATES: [&str; 4] = ["io-uring", "xsk-rs", "sc", "syscalls"];

/// Appended to `RUSTFLAGS`. `rustix_use_libc` is the cfg rustix's build script reads to select
/// its libc backend (rustix README, "set the RUSTFLAGS environment variable to
/// --cfg=rustix_use_libc"; rustix build.rs `CARGO_CFG_RUSTIX_USE_LIBC`). The `--check-cfg`
/// entries declare both cfgs so `unexpected_cfgs` does not warn about them
/// ([The rustc book: Checking conditional configurations](https://doc.rust-lang.org/rustc/check-cfg.html)).
const SNARE_RUSTFLAGS: [&str; 6] = [
    "--cfg",
    "snare",
    "--cfg",
    "rustix_use_libc",
    "--check-cfg=cfg(snare)",
    "--check-cfg=cfg(rustix_use_libc)",
];

/// The command line after the `snare` argument is dropped.
#[derive(Parser)]
#[command(
    name = "cargo-snare",
    bin_name = "cargo snare",
    version,
    about = "Run a crate's #[cfg(snare)] tests under the snare interposer"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
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
    /// Directory holding the drop-in syscall shims (io-uring, xsk-rs, sc, syscalls), used instead
    /// of the snare repository's tagged copy.
    #[arg(long, value_name = "DIR")]
    shims_dir: Option<PathBuf>,

    /// Git ref (tag, branch or commit) of the snare repository to take the shims from.
    #[arg(long, value_name = "REF", default_value = SHIMS_TAG, conflicts_with = "shims_dir")]
    shims_rev: String,

    /// Patch every shim, even ones not currently in the dependency graph.
    #[arg(long)]
    all_shims: bool,

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
    match Cli::parse_from(args).cmd {
        Cmd::Test(args) => exit(run_test(args)),
    }
}

/// Runs (or, with `--dry-run`, prints) `cargo test` with the shims patched in and the snare cfgs
/// appended to `RUSTFLAGS`, returning the exit code to use: cargo's own, or 1 if it could not be
/// started or died by a signal.
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
    let patches = match resolve_shims(args.shims_dir.as_deref(), args.all_shims) {
        Ok(patches) => patches,
        Err(code) => return code,
    };

    let mut cmd = Command::new("cargo");
    cmd.arg("test");
    for name in &patches {
        match &args.shims_dir {
            Some(dir) => {
                cmd.arg("--config").arg(format!(
                    "patch.crates-io.{name}.path={}",
                    toml_string(&dir.join(name))
                ));
            }
            None => {
                cmd.arg("--config")
                    .arg(format!("patch.crates-io.{name}.git=\"{SHIMS_GIT}\""))
                    .arg("--config")
                    .arg(format!("patch.crates-io.{name}.rev=\"{}\"", args.shims_rev));
            }
        }
    }
    cmd.args(&args.cargo_args);

    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    for flag in SNARE_RUSTFLAGS {
        if !rustflags.is_empty() {
            rustflags.push(' ');
        }
        rustflags.push_str(flag);
    }
    cmd.env("RUSTFLAGS", rustflags);

    if args.dry_run {
        print_invocation(&cmd, &patches);
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

/// The shims to patch: those available (all of [`SHIM_CRATES`] from git, or the subdirectories
/// of `shims_dir` with a `Cargo.toml`) and, unless `all`, used somewhere in the current
/// workspace's dependency graph. Patching an unused crate is harmless but makes cargo warn that
/// the patch was not used. `Err` carries the exit code when no shim exists or `cargo metadata`
/// fails.
fn resolve_shims(shims_dir: Option<&Path>, all: bool) -> Result<Vec<&'static str>, i32> {
    let present: Vec<&'static str> = SHIM_CRATES
        .into_iter()
        .filter(|name| shims_dir.is_none_or(|dir| dir.join(name).join("Cargo.toml").is_file()))
        .collect();

    if present.is_empty() {
        eprintln!(
            "cargo-snare: no shims found under {}",
            shims_dir.unwrap_or(Path::new("")).display()
        );
        return Err(1);
    }
    if all {
        return Ok(present);
    }

    let graph = dependency_names()?;
    Ok(present
        .into_iter()
        .filter(|name| graph.iter().any(|dep| dep == name))
        .collect())
}

/// The [`SHIM_CRATES`] that appear in `cargo metadata --format-version 1` for the current
/// directory ([The Cargo Book: cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)).
/// A textual match on `"name":"<crate>"` rather than a JSON parse: cargo prints compact JSON, and
/// a false positive (another field named `name` with that value) only adds a harmless patch.
/// `Err` carries the exit code if `cargo metadata` fails or cannot be run.
fn dependency_names() -> Result<Vec<String>, i32> {
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
    let json = String::from_utf8_lossy(&output.stdout);
    Ok(SHIM_CRATES
        .iter()
        .filter(|name| json.contains(&format!("\"name\":\"{name}\"")))
        .map(|name| name.to_string())
        .collect())
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

/// Prints which shims are patched and the command as a shell line, `RUSTFLAGS` included, for
/// `--dry-run`. The arguments are not shell-quoted.
fn print_invocation(cmd: &Command, patches: &[&'static str]) {
    if patches.is_empty() {
        println!("cargo-snare: no shim crates in the dependency graph; none patched");
    } else {
        println!("cargo-snare: patching {}", patches.join(", "));
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
