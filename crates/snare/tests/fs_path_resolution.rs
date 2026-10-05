#![cfg(unix)]

use std::fs::{File, OpenOptions};
use std::path::Path;

use snare::{FsBuilder, Sim};

fn errno<T>(result: std::io::Result<T>) -> i32 {
    result
        .err()
        .map_or(0, |error| error.raw_os_error().unwrap())
}

fn traversal_errors(root: &Path) -> Vec<i32> {
    let mut errors = Vec::new();
    for path in [
        "missing/../existing",
        "file/../existing",
        "missing/./../existing",
        "file/./../existing",
        "directory/missing/../../existing",
        "directory/../file/../existing",
        "file/.",
        "file/..",
        "missing/..",
    ] {
        let path = root.join(path);
        errors.extend([
            errno(File::open(&path)),
            errno(OpenOptions::new().write(true).create_new(true).open(&path)),
            errno(std::fs::metadata(&path)),
            errno(std::fs::symlink_metadata(&path)),
            errno(std::fs::create_dir(&path)),
            errno(std::fs::remove_file(&path)),
            errno(std::fs::rename(&path, root.join("target"))),
            errno(std::fs::rename(root.join("existing"), &path)),
            errno(std::fs::read_dir(&path)),
            errno(std::fs::canonicalize(&path)),
        ]);
    }
    errors
}

#[test]
fn intermediate_components_are_resolved_before_parent_components_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-fs-resolution-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("existing"), b"contents").unwrap();
    std::fs::write(root.join("file"), b"intermediate").unwrap();
    std::fs::create_dir(root.join("directory")).unwrap();
    let native = traversal_errors(&root);
    assert!(
        native
            .as_chunks::<10>()
            .0
            .iter()
            .all(|errors| errors[..9].iter().all(|&error| error != 0)),
        "{native:?}"
    );
    std::fs::remove_dir_all(&root).unwrap();
    for deterministic in [false, true] {
        let fs = FsBuilder::new()
            .own_prefix(&root)
            .file(root.join("existing"), "contents")
            .file(root.join("file"), "intermediate")
            .dir(root.join("directory"))
            .build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        let modeled = sim.run(|| traversal_errors(&root));
        assert_eq!(modeled, native, "deterministic={deterministic}");
        assert!(!root.exists());
    }
}

#[test]
fn declared_directories_allow_parent_traversal_and_creation_without_host_parents() {
    let root = "/snare-path-resolution-mount";
    let fs = FsBuilder::new().dir(root).own_prefix(root).build();
    Sim::builder().fs(fs).build().run(|| {
        std::fs::create_dir(format!("{root}/directory")).unwrap();
        std::fs::write(format!("{root}/directory/../existing"), b"contents").unwrap();
        assert_eq!(
            std::fs::read(format!("{root}/./existing")).unwrap(),
            b"contents"
        );
        std::fs::rename(
            format!("{root}/directory/../existing"),
            format!("{root}/directory/./renamed"),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(format!("{root}/directory/../directory/renamed")).unwrap(),
            b"contents"
        );
        std::fs::remove_file(format!("{root}/directory/../directory/renamed")).unwrap();
        assert!(!std::path::Path::new(&format!("{root}/directory/renamed")).exists());
    });
}

#[test]
fn explicit_passthrough_and_deny_take_precedence_over_virtual_traversal() {
    let root =
        std::env::temp_dir().join(format!("snare-fs-resolution-policy-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("real_directory")).unwrap();
    std::fs::write(root.join("existing"), b"real contents").unwrap();
    let fs = FsBuilder::new()
        .dir(&root)
        .own_prefix(&root)
        .passthrough(root.join("existing").to_str().unwrap())
        .deny(root.join("secret").to_str().unwrap())
        .build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(
            std::fs::read(root.join("real_directory/../existing")).unwrap(),
            b"real contents"
        );
        assert_eq!(
            errno(File::open(root.join("missing/../secret"))),
            libc::EACCES
        );
    });
    std::fs::remove_dir_all(root).unwrap();
}

fn terminal_dot_rename_errors(root: &Path) -> Vec<i32> {
    [
        (root.join("directory/."), root.join("moved")),
        (root.join("directory/.."), root.join("moved")),
        (root.join("file"), root.join("directory/.")),
        (root.join("file"), root.join("directory/..")),
    ]
    .into_iter()
    .map(|(from, to)| errno(std::fs::rename(from, to)))
    .collect()
}

#[test]
fn renames_do_not_replace_terminal_dot_components_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-rename-dots-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("directory")).unwrap();
    std::fs::write(root.join("file"), b"contents").unwrap();
    let native = terminal_dot_rename_errors(&root);
    assert!(native.iter().all(|&error| error != 0), "{native:?}");
    std::fs::remove_dir_all(&root).unwrap();
    let sim = Sim::builder()
        .fs(FsBuilder::new()
            .own_prefix(&root)
            .file(root.join("file"), "contents")
            .dir(root.join("directory"))
            .build())
        .build();
    assert_eq!(sim.run(|| terminal_dot_rename_errors(&root)), native);
}
