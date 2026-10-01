//! `cargo snare` — build and run a crate's `#[cfg(snare)]` tests under the snare interposer.
//!
//! Cargo invokes an external subcommand `cargo snare <args>` as `cargo-snare snare <args>`, so the
//! first argument is the subcommand's own name and is dropped before parsing.

use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use clap::{Args, Parser, Subcommand};

const DEFAULT_SHIMS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../shims");

const SHIM_CRATES: [&str; 4] = ["io-uring", "xsk-rs", "sc", "syscalls"];

const SNARE_RUSTFLAGS: [&str; 6] = [
    "--cfg",
    "snare",
    "--cfg",
    "rustix_use_libc",
    "--check-cfg=cfg(snare)",
    "--check-cfg=cfg(rustix_use_libc)",
];

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

#[derive(Subcommand)]
enum Cmd {
    /// Build and run the crate's tests with `--cfg snare` and the syscall shims patched in.
    Test(TestArgs),
}

#[derive(Args)]
struct TestArgs {
    /// Directory holding the drop-in syscall shims (io-uring, xsk-rs, sc, syscalls).
    #[arg(long, value_name = "DIR", default_value = DEFAULT_SHIMS_DIR)]
    shims_dir: PathBuf,

    /// Patch every shim, even ones not currently in the dependency graph.
    #[arg(long)]
    all_shims: bool,

    /// Print the assembled cargo invocation instead of running it.
    #[arg(long)]
    dry_run: bool,

    /// Arguments forwarded verbatim to `cargo test` (e.g. `--test foo -- --nocapture`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "CARGO_ARGS")]
    cargo_args: Vec<String>,
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("snare") {
        args.remove(1);
    }
    match Cli::parse_from(args).cmd {
        Cmd::Test(args) => exit(run_test(args)),
    }
}

fn run_test(args: TestArgs) -> i32 {
    let patches = match resolve_shims(&args.shims_dir, args.all_shims) {
        Ok(patches) => patches,
        Err(code) => return code,
    };

    let mut cmd = Command::new("cargo");
    cmd.arg("test");
    for (name, path) in &patches {
        cmd.arg("--config")
            .arg(format!("patch.crates-io.{name}.path={}", toml_string(path)));
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

fn resolve_shims(shims_dir: &Path, all: bool) -> Result<Vec<(&'static str, PathBuf)>, i32> {
    let present: Vec<(&'static str, PathBuf)> = SHIM_CRATES
        .iter()
        .map(|name| (*name, shims_dir.join(name)))
        .filter(|(_, path)| path.join("Cargo.toml").is_file())
        .collect();

    if present.is_empty() {
        eprintln!(
            "cargo-snare: no shims found under {}; pass --shims-dir",
            shims_dir.display()
        );
        return Err(1);
    }
    if all {
        return Ok(present);
    }

    let graph = dependency_names()?;
    Ok(present
        .into_iter()
        .filter(|(name, _)| graph.iter().any(|dep| dep == name))
        .collect())
}

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

fn toml_string(path: &Path) -> String {
    let escaped = path.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn print_invocation(cmd: &Command, patches: &[(&'static str, PathBuf)]) {
    if patches.is_empty() {
        println!("cargo-snare: no shim crates in the dependency graph; none patched");
    } else {
        let names: Vec<&str> = patches.iter().map(|(n, _)| *n).collect();
        println!("cargo-snare: patching {}", names.join(", "));
    }
    print!("RUSTFLAGS='");
    if let Some(flags) = cmd.get_envs().find_map(|(k, v)| (k == "RUSTFLAGS").then_some(v).flatten()) {
        print!("{}", flags.to_string_lossy());
    }
    print!("' cargo");
    for arg in cmd.get_args() {
        print!(" {}", arg.to_string_lossy());
    }
    println!();
}
