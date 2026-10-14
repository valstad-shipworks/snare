#![cfg(windows)]

//! The isolated environment on Windows (`SimBuilder::env` / `isolate_env`): what `std::env` sees,
//! which threads and runs see it, a child process inheriting it, and the Win32 and C runtime
//! environment calls against the real process environment, the same calls on the same fresh names
//! made in a sim and under `snare::real` and their results compared whole (return values, last
//! errors, `errno`, every buffer element).

use std::ffi::{CStr, c_char, c_int, c_void};
use std::process::Command;

use snare::Sim;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;
    fn GetEnvironmentVariableA(name: *const u8, buffer: *mut u8, size: u32) -> u32;
    fn SetEnvironmentVariableW(name: *const u16, value: *const u16) -> i32;
    fn SetEnvironmentVariableA(name: *const u8, value: *const u8) -> i32;
    fn GetEnvironmentStringsW() -> *mut u16;
    fn GetEnvironmentStringsA() -> *mut u8;
    fn FreeEnvironmentStringsW(block: *mut u16) -> i32;
    fn FreeEnvironmentStringsA(block: *mut u8) -> i32;
    fn SetEnvironmentStringsW(block: *const u16) -> i32;
    fn ExpandEnvironmentStringsW(source: *const u16, destination: *mut u16, size: u32) -> u32;
    fn ExpandEnvironmentStringsA(source: *const u8, destination: *mut u8, size: u32) -> u32;
}

unsafe extern "C" {
    fn getenv(name: *const c_char) -> *mut c_char;
    fn _wgetenv(name: *const u16) -> *mut u16;
    fn _putenv(option: *const c_char) -> c_int;
    fn _wputenv(option: *const u16) -> c_int;
    fn _putenv_s(name: *const c_char, value: *const c_char) -> c_int;
    fn _wputenv_s(name: *const u16, value: *const u16) -> c_int;
    fn getenv_s(
        required: *mut usize,
        buffer: *mut c_char,
        count: usize,
        name: *const c_char,
    ) -> c_int;
    fn _wgetenv_s(required: *mut usize, buffer: *mut u16, count: usize, name: *const u16) -> c_int;
    fn _dupenv_s(buffer: *mut *mut c_char, count: *mut usize, name: *const c_char) -> c_int;
    fn _wdupenv_s(buffer: *mut *mut u16, count: *mut usize, name: *const u16) -> c_int;
    fn _errno() -> *mut c_int;
    fn free(block: *mut c_void);
}

/// Serializes the tests that change the real environment or read it under `snare::real`.
fn real_env() -> std::sync::MutexGuard<'static, ()> {
    static REAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    REAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn a(s: &[u8]) -> Vec<u8> {
    s.iter().copied().chain([0]).collect()
}

fn errno() -> c_int {
    unsafe { *_errno() }
}

fn set_errno(value: c_int) {
    unsafe { *_errno() = value };
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn wide_str(at: *const u16) -> Option<String> {
    if at.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { *at.add(length) } != 0 {
        length += 1;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(at, length)
    }))
}

fn narrow_str(at: *const c_char) -> Option<Vec<u8>> {
    (!at.is_null()).then(|| unsafe { CStr::from_ptr(at) }.to_bytes().to_vec())
}

fn block_entries(block: *const u16) -> Vec<String> {
    let mut entries = Vec::new();
    let mut at = block;
    while let Some(entry) = wide_str(at).filter(|entry| !entry.is_empty()) {
        at = unsafe { at.add(entry.encode_utf16().count() + 1) };
        entries.push(entry);
    }
    entries
}

#[test]
fn std_reads_and_writes_the_simulated_environment() {
    let _real = real_env();
    snare::real(|| unsafe { std::env::set_var("SNARE_ENV_STD_REAL", "real") });
    let sim = Sim::builder()
        .env("SNARE_ENV_STD", "declared")
        .env("SNARE_ENV_STD_EMPTY", "")
        .build();
    sim.run(|| {
        assert_eq!(std::env::var("SNARE_ENV_STD").as_deref(), Ok("declared"));
        assert_eq!(std::env::var("SNARE_ENV_STD_EMPTY").as_deref(), Ok(""));
        assert_eq!(
            std::env::var("SNARE_ENV_STD_REAL"),
            Err(std::env::VarError::NotPresent)
        );
        assert!(std::env::var_os("PATH").is_none());
        unsafe { std::env::set_var("SNARE_ENV_STD_SET", "x".repeat(2000)) };
        assert_eq!(std::env::var("SNARE_ENV_STD_SET"), Ok("x".repeat(2000)));
        unsafe { std::env::remove_var("SNARE_ENV_STD") };
        assert!(std::env::var("SNARE_ENV_STD").is_err());
        unsafe { std::env::remove_var("SNARE_ENV_STD_NEVER") };
    });
    assert!(
        std::env::var("SNARE_ENV_STD_SET").is_err(),
        "the process never saw it"
    );
    assert_eq!(std::env::var("SNARE_ENV_STD_REAL").as_deref(), Ok("real"));
    sim.run(|| {
        assert_eq!(
            std::env::var("SNARE_ENV_STD_SET"),
            Ok("x".repeat(2000)),
            "kept across runs"
        );
        assert!(std::env::var("SNARE_ENV_STD").is_err());
    });
    unsafe { std::env::remove_var("SNARE_ENV_STD_REAL") };
}

#[test]
fn names_compare_without_regard_to_case_and_keep_their_first_spelling() {
    Sim::builder()
        .env("Path", "first")
        .env("PATH", "second")
        .build()
        .run(|| {
            assert_eq!(std::env::var("path").as_deref(), Ok("second"));
            unsafe { std::env::set_var("PATH", "third") };
            let vars: Vec<(String, String)> = std::env::vars().collect();
            assert_eq!(vars, [("Path".to_string(), "third".to_string())]);
        });
}

#[test]
fn vars_lists_only_the_simulated_block_in_its_order() {
    let got = Sim::builder()
        .env("b_var", "2")
        .env("A_VAR", "1")
        .env("=C:", "C:\\sim")
        .build()
        .run(|| {
            unsafe { std::env::set_var("C_VAR", "3") };
            std::env::vars().collect::<Vec<_>>()
        });
    assert_eq!(
        got,
        [
            ("=C:", "C:\\sim"),
            ("A_VAR", "1"),
            ("b_var", "2"),
            ("C_VAR", "3")
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[test]
fn an_isolated_environment_with_no_variables_is_empty() {
    Sim::builder().isolate_env().build().run(|| {
        assert_eq!(std::env::vars_os().count(), 0);
        let block = unsafe { GetEnvironmentStringsW() };
        assert_eq!(unsafe { [*block, *block.add(1)] }, [0, 0]);
        assert_eq!(unsafe { FreeEnvironmentStringsW(block) }, 1);
        assert!(unsafe { getenv(c"PATH".as_ptr()) }.is_null());
    });
}

#[test]
#[should_panic(expected = "is not a Windows environment variable name")]
fn a_name_windows_refuses_panics_at_build() {
    let _ = Sim::builder().env("A=B", "v").build();
}

#[test]
fn two_sims_keep_their_own_environments() {
    let a = Sim::builder().env("WHO", "a").build();
    let b = Sim::builder().env("WHO", "b").build();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            a.run(|| {
                unsafe { std::env::set_var("ONLY_A", "1") };
                assert_eq!(std::env::var("WHO").as_deref(), Ok("a"));
            })
        });
        scope.spawn(|| {
            b.run(|| {
                unsafe { std::env::remove_var("WHO") };
                assert!(std::env::var("ONLY_A").is_err());
            })
        });
    });
    a.run(|| assert_eq!(std::env::var("ONLY_A").as_deref(), Ok("1")));
    b.run(|| assert!(std::env::var("WHO").is_err()));
}

#[test]
fn which_threads_see_the_isolated_environment() {
    let _real = real_env();
    let key = "SNARE_ENV_THREADS";
    snare::real(|| unsafe { std::env::set_var(key, "real") });
    Sim::builder().env(key, "sim").build().run(|| {
        assert_eq!(std::env::var(key).as_deref(), Ok("sim"));
        let spawned = std::thread::spawn(move || std::env::var(key))
            .join()
            .unwrap();
        assert_eq!(spawned.as_deref(), Ok("sim"));
        assert_eq!(snare::real(|| std::env::var(key)).as_deref(), Ok("real"));
        let unmanaged = snare::real(|| std::thread::spawn(move || std::env::var(key)))
            .join()
            .unwrap();
        assert_eq!(unmanaged.as_deref(), Ok("real"));
        assert_eq!(std::env::var(key).as_deref(), Ok("sim"));
    });
    unsafe { std::env::remove_var(key) };
}

#[test]
fn an_unisolated_sim_writes_through_to_the_real_environment() {
    let _real = real_env();
    let key = "SNARE_ENV_THROUGH";
    let sim = Sim::new();
    sim.run(|| unsafe { std::env::set_var(key, "from-sim") });
    assert_eq!(std::env::var(key).as_deref(), Ok("from-sim"));
    sim.run(|| unsafe { std::env::remove_var(key) });
    assert!(std::env::var(key).is_err());
}

#[test]
fn a_child_process_inherits_the_simulated_environment() {
    let _real = real_env();
    let echo = || {
        let inherited = Command::new("cmd")
            .args(["/c", "echo %SNARE_ENV_CHILD%"])
            .output()
            .unwrap();
        let added = Command::new("cmd")
            .args(["/c", "echo %SNARE_ENV_CHILD%-%SNARE_ENV_ADDED%"])
            .env("SNARE_ENV_ADDED", "added")
            .output()
            .unwrap();
        [inherited, added].map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    assert_eq!(
        snare::real(echo),
        ["%SNARE_ENV_CHILD%", "%SNARE_ENV_CHILD%-added"]
    );
    let got = Sim::builder()
        .env("SNARE_ENV_CHILD", "sim")
        .build()
        .run(echo);
    assert_eq!(got, ["sim", "sim-added"]);
}

/// The names [`win32_probe`] and [`crt_probe`] use, none of which the real environment holds.
const PREFIX: &str = "SNARE_ENVT_";

fn name(suffix: &str) -> String {
    format!("{PREFIX}{suffix}")
}

/// Win32 environment calls on fresh names, each result recorded: what a sim must answer exactly
/// as the real environment does.
fn win32_probe() -> Vec<String> {
    let mut log = Vec::new();
    let set_w = |log: &mut Vec<String>, label: &str, n: Option<&str>, v: Option<&str>| {
        let (n, v) = (n.map(w), v.map(w));
        unsafe { SetLastError(1234) };
        let r = unsafe {
            SetEnvironmentVariableW(
                n.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                v.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            )
        };
        log.push(format!("set_w {label}: {r} {}", last_error()));
    };
    let get_w = |log: &mut Vec<String>, n: &str, size: u32| {
        let n16 = w(n);
        let mut buffer = vec![0x5555u16; 12];
        unsafe { SetLastError(1234) };
        let r = unsafe {
            GetEnvironmentVariableW(
                n16.as_ptr(),
                if size == u32::MAX {
                    std::ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                if size == u32::MAX { 0 } else { size },
            )
        };
        log.push(format!(
            "get_w {n} {size}: {r} {} {buffer:x?}",
            last_error()
        ));
    };
    let get_a = |log: &mut Vec<String>, n: &[u8], size: u32| {
        let n8 = a(n);
        let mut buffer = vec![0x55u8; 12];
        unsafe { SetLastError(1234) };
        let r = unsafe { GetEnvironmentVariableA(n8.as_ptr(), buffer.as_mut_ptr(), size) };
        log.push(format!(
            "get_a {n:x?} {size}: {r} {} {buffer:x?}",
            last_error()
        ));
    };
    let expand_w = |log: &mut Vec<String>, source: &str, size: u32| {
        let s = w(source);
        let mut buffer = vec![0x5555u16; 32];
        unsafe { SetLastError(1234) };
        let r = unsafe {
            ExpandEnvironmentStringsW(
                s.as_ptr(),
                if size == u32::MAX {
                    std::ptr::null_mut()
                } else {
                    buffer.as_mut_ptr()
                },
                if size == u32::MAX { 0 } else { size },
            )
        };
        log.push(format!(
            "expand_w {source} {size}: {r} {} {buffer:x?}",
            last_error()
        ));
    };
    let expand_a = |log: &mut Vec<String>, source: &[u8], size: u32| {
        let s = a(source);
        let mut buffer = vec![0x55u8; 32];
        unsafe { SetLastError(1234) };
        let r = unsafe { ExpandEnvironmentStringsA(s.as_ptr(), buffer.as_mut_ptr(), size) };
        log.push(format!(
            "expand_a {source:x?} {size}: {r} {} {buffer:x?}",
            last_error()
        ));
    };

    let hello = name("HELLO");
    set_w(&mut log, "hello", Some(&hello), Some("hello"));
    for size in [0, 1, 5, 6, 7, u32::MAX] {
        get_w(&mut log, &hello, size);
        get_w(&mut log, &hello.to_lowercase(), size);
    }
    let empty = name("EMPTY");
    set_w(&mut log, "empty", Some(&empty), Some(""));
    for size in [0, 1, 2, u32::MAX] {
        get_w(&mut log, &empty, size);
    }
    for n in [
        name("MISSING"),
        String::new(),
        format!("{hello}=hello"),
        "=".into(),
    ] {
        get_w(&mut log, &n, 12);
    }
    set_w(
        &mut log,
        "name with =",
        Some(&format!("{hello}=X")),
        Some("v"),
    );
    set_w(&mut log, "empty name", Some(""), Some("v"));
    set_w(
        &mut log,
        "=-prefixed",
        Some(&format!("={PREFIX}EQ")),
        Some("eq"),
    );
    get_w(&mut log, &format!("={PREFIX}EQ"), 12);
    set_w(
        &mut log,
        "=-prefixed with =",
        Some(&format!("={PREFIX}EQ=Z")),
        Some("v"),
    );
    set_w(&mut log, "remove unset", Some(&name("NEVER")), None);
    set_w(&mut log, "remove empty name", Some(""), None);
    set_w(&mut log, "value with =", Some(&name("EQV")), Some("a=b=c"));
    get_w(&mut log, &name("EQV"), 12);
    set_w(&mut log, "spelling", Some(&name("Mixed")), Some("1"));
    set_w(&mut log, "respelt", Some(&name("MIXED")), Some("2"));
    for suffix in ["ZZZ", "aaa", "Mmm", "_u", "~t", "[b", "Ä", "ä"] {
        set_w(&mut log, suffix, Some(&name(suffix)), Some(suffix));
    }
    let ours = |entry: &String| {
        entry.to_uppercase().starts_with(PREFIX) || entry.starts_with(&format!("={PREFIX}"))
    };
    let block = unsafe { GetEnvironmentStringsW() };
    let entries: Vec<String> = block_entries(block).into_iter().filter(ours).collect();
    log.push(format!("block_w {entries:?} free {}", unsafe {
        FreeEnvironmentStringsW(block)
    }));
    let block = unsafe { GetEnvironmentStringsA() };
    let mut entries = Vec::new();
    let mut at = block;
    while let Some(entry) = narrow_str(at.cast()).filter(|entry| !entry.is_empty()) {
        at = unsafe { at.add(entry.len() + 1) };
        if entry.to_ascii_uppercase().starts_with(PREFIX.as_bytes()) {
            entries.push(format!("{entry:x?}"));
        }
    }
    log.push(format!("block_a {entries:?} free {}", unsafe {
        FreeEnvironmentStringsA(block)
    }));

    let latin = name("LATIN");
    let n8 = a(latin.as_bytes());
    unsafe { SetLastError(1234) };
    let r = unsafe { SetEnvironmentVariableA(n8.as_ptr(), a(b"\xe9x").as_ptr()) };
    log.push(format!("set_a latin: {r} {}", last_error()));
    get_w(&mut log, &latin, 12);
    set_w(&mut log, "cjk", Some(&name("CJK")), Some("中x"));
    for size in [0, 1, 2, 3, 12] {
        get_a(&mut log, latin.as_bytes(), size);
        get_a(&mut log, name("CJK").as_bytes(), size);
    }
    get_a(&mut log, name("MISSING").as_bytes(), 12);
    get_a(&mut log, empty.as_bytes(), 0);
    get_a(&mut log, empty.as_bytes(), 12);
    for length in [32766usize, 32767, 65535] {
        let long = name("LONG");
        let value = vec![b'q'; length];
        unsafe { SetLastError(1234) };
        let r = unsafe { SetEnvironmentVariableA(a(long.as_bytes()).as_ptr(), a(&value).as_ptr()) };
        log.push(format!("set_a {length}: {r} {}", last_error()));
        set_w(&mut log, "long", Some(&long), Some(&"y".repeat(length)));
        let mut buffer = vec![0u8; 70000];
        for size in [10, 70000] {
            unsafe { SetLastError(1234) };
            let r = unsafe {
                GetEnvironmentVariableA(a(long.as_bytes()).as_ptr(), buffer.as_mut_ptr(), size)
            };
            log.push(format!("get_a {length} {size}: {r} {}", last_error()));
            unsafe { SetLastError(1234) };
            let r = unsafe {
                ExpandEnvironmentStringsA(
                    a(format!("%{long}%").as_bytes()).as_ptr(),
                    buffer.as_mut_ptr(),
                    size,
                )
            };
            log.push(format!("expand_a {length} {size}: {r} {}", last_error()));
        }
        let mut buffer = vec![0u16; 70000];
        unsafe { SetLastError(1234) };
        let r = unsafe {
            ExpandEnvironmentStringsW(w(&format!("%{long}%")).as_ptr(), buffer.as_mut_ptr(), 70000)
        };
        log.push(format!("expand_w {length}: {r} {}", last_error()));
        set_w(&mut log, "long removed", Some(&long), None);
    }

    let e = name("E");
    set_w(&mut log, "e", Some(&e), Some("val"));
    for source in [
        format!("%{e}%x"),
        format!("ab%{e}%c"),
        "abcdef".to_string(),
        format!("%{e}%%{PREFIX}MISSING%cd"),
        format!("%{PREFIX}MISSING%"),
        format!("%{e}%%{e}%"),
        format!("<%{empty}%>"),
        "100%".to_string(),
        "a%%b".to_string(),
        format!("%%{e}%%"),
        String::new(),
        format!("%{}%", e.to_lowercase()),
        format!("%{e}=x%"),
    ] {
        for size in [0, 1, 2, 3, 4, 5, 6, 7, 8, 32, u32::MAX] {
            expand_w(&mut log, &source, size);
        }
        for size in [0, 3, 5, 6, 7, 8, 32] {
            expand_a(&mut log, source.as_bytes(), size);
        }
    }
    expand_a(&mut log, format!("%{PREFIX}CJK%").as_bytes(), 2);
    expand_a(&mut log, format!("%{PREFIX}CJK%").as_bytes(), 32);
    unsafe { SetLastError(1234) };
    let r = unsafe {
        ExpandEnvironmentStringsA(
            a(format!("%{e}%").as_bytes()).as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    log.push(format!("expand_a null: {r} {}", last_error()));

    let block = unsafe { GetEnvironmentStringsW() };
    for entry in block_entries(block) {
        let n = entry[..entry[1..].find('=').unwrap() + 1].to_string();
        if n.to_uppercase().starts_with(PREFIX) || n.starts_with(&format!("={PREFIX}")) {
            set_w(&mut log, "cleanup", Some(&n), None);
        }
    }
    unsafe { FreeEnvironmentStringsW(block) };
    log
}

#[test]
fn win32_calls_match_the_real_environment() {
    let _real = real_env();
    let real = snare::real(win32_probe);
    let sim = Sim::builder().isolate_env().build().run(win32_probe);
    for (real, sim) in real.iter().zip(&sim) {
        assert_eq!(sim, real);
    }
    assert_eq!(sim.len(), real.len());
}

/// C runtime environment calls on fresh names, after both of its tables exist: each result
/// recorded.
fn crt_probe() -> Vec<String> {
    let mut log = Vec::new();
    let cget = |log: &mut Vec<String>, n: &str| {
        let n8 = a(n.as_bytes());
        set_errno(77);
        let value = narrow_str(unsafe { getenv(n8.as_ptr().cast()) });
        log.push(format!("getenv {n}: {value:x?} {}", errno()));
    };
    let wget = |log: &mut Vec<String>, n: &str| {
        let value = wide_str(unsafe { _wgetenv(w(n).as_ptr()) });
        log.push(format!("_wgetenv {n}: {value:?}"));
    };
    let os = |log: &mut Vec<String>, n: &str| {
        let mut buffer = [0u16; 16];
        unsafe { SetLastError(1234) };
        let r = unsafe { GetEnvironmentVariableW(w(n).as_ptr(), buffer.as_mut_ptr(), 16) };
        log.push(format!("os {n}: {r} {} {buffer:x?}", last_error()));
    };
    let put = |log: &mut Vec<String>, option: &[u8]| {
        set_errno(77);
        let r = unsafe { _putenv(a(option).as_ptr().cast()) };
        log.push(format!("_putenv {option:x?}: {r} {}", errno()));
    };

    wget(&mut log, &name("FIRST"));
    let c = name("C");
    put(&mut log, format!("{c}=1").as_bytes());
    cget(&mut log, &c);
    cget(&mut log, &c.to_lowercase());
    wget(&mut log, &c);
    os(&mut log, &c);
    put(&mut log, format!("{}=2", c.to_lowercase()).as_bytes());
    cget(&mut log, &c);
    os(&mut log, &c);
    put(&mut log, format!("{c}=").as_bytes());
    cget(&mut log, &c);
    wget(&mut log, &c);
    os(&mut log, &c);
    let only_os = name("ONLY_OS");
    unsafe { SetEnvironmentVariableW(w(&only_os).as_ptr(), w("os").as_ptr()) };
    cget(&mut log, &only_os);
    wget(&mut log, &only_os);
    put(&mut log, format!("{only_os}=").as_bytes());
    os(&mut log, &only_os);
    for option in [
        name("NOEQ").into_bytes(),
        b"=x".to_vec(),
        format!("={PREFIX}Q=1").into_bytes(),
        Vec::new(),
        format!("{}=", name("NEVER")).into_bytes(),
        format!("{}=a=b", name("D")).into_bytes(),
        [name("HIGH").as_bytes(), b"=\xe4\xb8"].concat(),
    ] {
        put(&mut log, &option);
    }
    cget(&mut log, &name("D"));
    cget(&mut log, &format!("{}=a", name("D")));
    cget(&mut log, "");
    os(&mut log, &name("D"));
    wget(&mut log, &name("HIGH"));
    os(&mut log, &name("HIGH"));

    let s = a(name("S").as_bytes());
    for (n, v) in [
        (s.clone(), a(b"v")),
        (s.clone(), a(b"")),
        (a(format!("{}=X", name("S")).as_bytes()), a(b"v")),
        (a(b""), a(b"v")),
    ] {
        set_errno(77);
        let r = unsafe { _putenv_s(n.as_ptr().cast(), v.as_ptr().cast()) };
        log.push(format!("_putenv_s {n:x?} {v:x?}: {r} {}", errno()));
        cget(&mut log, &name("S"));
        os(&mut log, &name("S"));
    }
    let wide = name("W");
    let r = unsafe { _wputenv(w(&format!("{wide}=中")).as_ptr()) };
    log.push(format!("_wputenv: {r}"));
    cget(&mut log, &wide);
    wget(&mut log, &wide);
    os(&mut log, &wide);
    let r = unsafe { _wputenv_s(w(&name("W2")).as_ptr(), w("v").as_ptr()) };
    log.push(format!("_wputenv_s: {r}"));
    cget(&mut log, &name("W2"));

    let gs = name("GS");
    put(&mut log, format!("{gs}=hello").as_bytes());
    for size in [0usize, 5, 6, 64] {
        let mut required = 999usize;
        let mut buffer = [0x55u8; 16];
        set_errno(77);
        let r = unsafe {
            getenv_s(
                &mut required,
                if size == 0 {
                    std::ptr::null_mut()
                } else {
                    buffer.as_mut_ptr().cast()
                },
                size,
                a(gs.as_bytes()).as_ptr().cast(),
            )
        };
        log.push(format!(
            "getenv_s {size}: {r} {required} {} {buffer:x?}",
            errno()
        ));
        let mut wbuffer = [0x5555u16; 16];
        let r = unsafe {
            _wgetenv_s(
                &mut required,
                if size == 0 {
                    std::ptr::null_mut()
                } else {
                    wbuffer.as_mut_ptr()
                },
                size,
                w(&gs).as_ptr(),
            )
        };
        log.push(format!("_wgetenv_s {size}: {r} {required} {wbuffer:x?}"));
    }
    let mut required = 999usize;
    let mut buffer = [0x55u8; 16];
    let r = unsafe {
        getenv_s(
            &mut required,
            buffer.as_mut_ptr().cast(),
            16,
            a(name("NONE").as_bytes()).as_ptr().cast(),
        )
    };
    log.push(format!("getenv_s unset: {r} {required} {buffer:x?}"));
    let r = unsafe {
        getenv_s(
            &mut required,
            buffer.as_mut_ptr().cast(),
            16,
            std::ptr::null(),
        )
    };
    log.push(format!("getenv_s null name: {r} {required}"));
    for n in [gs.clone(), name("NONE")] {
        let mut copy: *mut c_char = std::ptr::dangling_mut();
        let mut count = 999usize;
        set_errno(77);
        let r = unsafe { _dupenv_s(&mut copy, &mut count, a(n.as_bytes()).as_ptr().cast()) };
        log.push(format!(
            "_dupenv_s {n}: {r} {count} {} {:x?}",
            errno(),
            narrow_str(copy)
        ));
        unsafe { free(copy.cast()) };
        let mut copy: *mut u16 = std::ptr::dangling_mut();
        let r = unsafe { _wdupenv_s(&mut copy, &mut count, w(&n).as_ptr()) };
        log.push(format!("_wdupenv_s {n}: {r} {count} {:?}", wide_str(copy)));
        unsafe { free(copy.cast()) };
    }
    let mut copy: *mut c_char = std::ptr::dangling_mut();
    let r = unsafe {
        _dupenv_s(
            &mut copy,
            std::ptr::null_mut(),
            a(gs.as_bytes()).as_ptr().cast(),
        )
    };
    log.push(format!("_dupenv_s no count: {r} {:x?}", narrow_str(copy)));
    unsafe { free(copy.cast()) };

    let first = unsafe { getenv(a(gs.as_bytes()).as_ptr().cast()) };
    put(&mut log, format!("{}=1", name("OTHER")).as_bytes());
    let after_other = unsafe { getenv(a(gs.as_bytes()).as_ptr().cast()) };
    log.push(format!(
        "stable across another change: {}",
        first == after_other
    ));

    let block = unsafe { GetEnvironmentStringsW() };
    for entry in block_entries(block) {
        let n = &entry[..entry[1..].find('=').unwrap() + 1];
        if n.to_uppercase().starts_with(PREFIX) {
            let r = unsafe { _wputenv(w(&format!("{n}=")).as_ptr()) };
            unsafe { SetEnvironmentVariableW(w(n).as_ptr(), std::ptr::null()) };
            log.push(format!("cleanup {n}: {r}"));
        }
    }
    unsafe { FreeEnvironmentStringsW(block) };
    log
}

#[test]
fn crt_calls_match_the_real_c_runtime() {
    let _real = real_env();
    let real = snare::real(crt_probe);
    let sim = Sim::builder().isolate_env().build().run(crt_probe);
    for (real, sim) in real.iter().zip(&sim) {
        assert_eq!(sim, real);
    }
    assert_eq!(sim.len(), real.len());
}

/// The C runtime's tables in a fresh sim, as in a fresh process (measured with a program entered
/// at `main` on Windows 11 ARM64): the narrow table holds the environment from the start and
/// misses a later `SetEnvironmentVariableW`, while the wide one is copied from the block when
/// first used and misses changes after that. Neither holds `=`-prefixed entries such as `=C:`.
#[test]
fn the_c_runtime_tables_start_from_the_sims_environment() {
    Sim::builder()
        .env("DECLARED", "1")
        .env("=C:", "C:\\sim")
        .build()
        .run(|| {
            assert_eq!(
                narrow_str(unsafe { getenv(c"DECLARED".as_ptr()) }),
                Some(b"1".to_vec())
            );
            unsafe { SetEnvironmentVariableW(w("LATER").as_ptr(), w("2").as_ptr()) };
            assert!(unsafe { getenv(c"LATER".as_ptr()) }.is_null());
            assert_eq!(
                wide_str(unsafe { _wgetenv(w("LATER").as_ptr()) }).as_deref(),
                Some("2")
            );
            assert!(unsafe { _wgetenv(w("=C:").as_ptr()) }.is_null());
            unsafe { SetEnvironmentVariableW(w("LATEST").as_ptr(), w("3").as_ptr()) };
            assert!(unsafe { _wgetenv(w("LATEST").as_ptr()) }.is_null());
            assert_eq!(std::env::var("LATEST").as_deref(), Ok("3"));
        });
}

/// `SetEnvironmentStringsW` replaces the block as given, measured: entries keep their order and
/// repeats, the first of a repeated name answers, and an empty block or an entry without a `=`
/// past its first character fails with `ERROR_INVALID_PARAMETER` and changes nothing.
#[test]
fn set_environment_strings_replaces_the_block() {
    let block = |entries: &[&str]| -> Vec<u16> {
        let mut block: Vec<u16> = entries.iter().flat_map(|e| w(e)).collect();
        block.push(0);
        block
    };
    Sim::builder().env("OLD", "1").build().run(|| {
        let set = |entries: &[&str]| {
            unsafe { SetLastError(1234) };
            let r = unsafe { SetEnvironmentStringsW(block(entries).as_ptr()) };
            (r, last_error())
        };
        assert_eq!(set(&["B=2", "a=1", "=C:=C:\\x", "c=", "b=3"]), (1, 1234));
        let vars: Vec<(String, String)> = std::env::vars().collect();
        let expected = [
            ("B", "2"),
            ("a", "1"),
            ("=C:", "C:\\x"),
            ("c", ""),
            ("b", "3"),
        ];
        assert_eq!(vars, expected.map(|(k, v)| (k.to_string(), v.to_string())));
        assert_eq!(std::env::var("b").as_deref(), Ok("2"));
        assert_eq!(set(&["X=1", "NOEQ"]), (0, 87));
        assert_eq!(set(&["Y=1", "=x"]), (0, 87));
        assert_eq!(set(&[]), (0, 87));
        assert_eq!(std::env::vars().count(), 5);
    });
}
