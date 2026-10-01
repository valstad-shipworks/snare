//! Give code under test a deterministic, isolated environment.
//!
//! Run with: `cargo run -p snare --example env_isolation`
//!
//! `HostProfile::env` declares variables the code reads with `std::env::var` (which calls
//! `getenv(3)`). Declaring any variable isolates the environment, so whatever is set on the real
//! machine — including `PATH` — is invisible inside the sim. `std::env::set_var` (`setenv(3)`) made
//! inside the run lands in the simulated environment only.

#[cfg(unix)]
fn main() {
    use snare::{HostProfile, Sim};

    let host = HostProfile::new()
        .env("APP_ENV", "staging")
        .env("DATABASE_URL", "postgres://sim/db")
        .build();

    let sim = Sim::builder().host(host).build();
    let summary = sim.run(|| {
        let app_env = std::env::var("APP_ENV").unwrap();
        let db = std::env::var("DATABASE_URL").unwrap();
        let real_home_hidden = std::env::var("HOME").is_err();

        unsafe { std::env::set_var("REQUEST_ID", "abc-123") };
        let req = std::env::var("REQUEST_ID").unwrap();

        format!("APP_ENV={app_env} DATABASE_URL={db} HOME_hidden={real_home_hidden} REQUEST_ID={req}")
    });

    println!("env_isolation: {summary}");
    // The runtime mutation stayed inside the sim; the real environment is untouched.
    assert!(std::env::var("REQUEST_ID").is_err());
}

#[cfg(not(unix))]
fn main() {
    println!("env_isolation: environment interposition is a unix-only feature");
}
