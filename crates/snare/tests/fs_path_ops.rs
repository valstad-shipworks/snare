#![cfg(unix)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use snare::{FsBuilder, Sim};

fn read_file(file: &mut File) -> Vec<u8> {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    contents
}

fn file_moves(root: &Path) -> (Vec<Vec<u8>>, Vec<bool>, Vec<u64>) {
    let directory = root.join("child");
    std::fs::create_dir(&directory).unwrap();
    let source = directory.join("source");
    let target = directory.join("target");
    std::fs::write(&source, b"source").unwrap();
    std::fs::write(&target, b"target").unwrap();
    let mut source_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    let mut target_fd = File::open(&target).unwrap();
    let source_inode = source_fd.metadata().unwrap().ino();
    let target_inode = target_fd.metadata().unwrap().ino();
    std::fs::rename(&source, &target).unwrap();
    let same_inode = std::fs::metadata(&target).unwrap().ino() == source_inode;
    let target_links = target_fd.metadata().unwrap().nlink();
    source_fd.seek(SeekFrom::End(0)).unwrap();
    source_fd.write_all(b"!").unwrap();
    let renamed_contents = std::fs::read(&target).unwrap();
    std::fs::remove_file(&target).unwrap();
    let unlinked_links = source_fd.metadata().unwrap().nlink();
    std::fs::write(&target, b"new").unwrap();
    let recreated_inode = std::fs::metadata(&target).unwrap().ino();
    (
        vec![
            renamed_contents,
            read_file(&mut source_fd),
            read_file(&mut target_fd),
            std::fs::read(&target).unwrap(),
        ],
        vec![
            same_inode,
            source_inode != target_inode,
            recreated_inode != source_inode,
            recreated_inode != target_inode,
            !source.exists(),
        ],
        vec![target_links, unlinked_links],
    )
}

#[test]
fn rename_replace_and_unlink_preserve_open_inodes_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-fs-path-files-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let native = file_moves(&root);
    std::fs::remove_dir_all(&root).unwrap();
    let path = root.to_str().unwrap();
    let fs = FsBuilder::new().dir(path).own_prefix(path).build();
    let modeled = Sim::builder().fs(fs).build().run(|| file_moves(&root));
    assert_eq!(modeled, native);
    assert!(!root.exists());
}

fn directory_moves(root: &Path) -> (Vec<u8>, bool, bool, Vec<String>) {
    let source = root.join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(source.join("nested")).unwrap();
    std::fs::write(source.join("nested/file"), b"contents").unwrap();
    let inode = std::fs::metadata(&source).unwrap().ino();
    let target = root.join("target");
    std::fs::rename(&source, &target).unwrap();
    let mut names: Vec<String> = std::fs::read_dir(target.join("nested"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    (
        std::fs::read(target.join("nested/file")).unwrap(),
        inode == std::fs::metadata(&target).unwrap().ino(),
        !source.exists(),
        names,
    )
}

#[test]
fn renamed_directories_keep_their_inodes_and_children_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-fs-path-dirs-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let native = directory_moves(&root);
    std::fs::remove_dir_all(&root).unwrap();
    let path = root.to_str().unwrap();
    let fs = FsBuilder::new().dir(path).own_prefix(path).build();
    let modeled = Sim::builder().fs(fs).build().run(|| directory_moves(&root));
    assert_eq!(modeled, native);
    assert!(!root.exists());
}

fn linked_files(root: &Path) -> (Vec<u64>, Vec<bool>, Vec<u8>) {
    let from = root.join("from");
    let to = root.join("to");
    std::fs::write(&from, b"data").unwrap();
    let file = File::open(&from).unwrap();
    std::fs::hard_link(&from, &to).unwrap();
    let mut links = vec![file.metadata().unwrap().nlink()];
    let same = std::fs::metadata(&from).unwrap().ino() == std::fs::metadata(&to).unwrap().ino();
    std::fs::rename(&from, &to).unwrap();
    let retained = from.exists() && to.exists();
    std::fs::remove_file(&from).unwrap();
    links.push(file.metadata().unwrap().nlink());
    let contents = std::fs::read(&to).unwrap();
    std::fs::remove_file(&to).unwrap();
    links.push(file.metadata().unwrap().nlink());
    (links, vec![same, retained], contents)
}

#[test]
fn hard_links_share_content_and_rename_to_same_inode_is_a_noop_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-fs-hardlinks-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let native = linked_files(&root);
    std::fs::remove_dir(&root).unwrap();
    let fs = FsBuilder::new().dir(&root).own_prefix(&root).build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| linked_files(&root)),
        native
    );
    assert!(!root.exists());
}

fn path_errors(root: &Path) -> Vec<i32> {
    let file = root.join("file");
    let directory = root.join("directory");
    [
        std::fs::create_dir(&file),
        std::fs::create_dir(root.join("missing/nested")),
        std::fs::create_dir(file.join("nested")),
        std::fs::remove_file(&directory),
        std::fs::rename(&file, &directory),
        std::fs::rename(&directory, &file),
        std::fs::rename(&directory, directory.join("nested")),
        std::fs::rename(root.join("missing"), root.join("new")),
        std::fs::rename(root.join("missing"), root.join("missing")),
        std::fs::create_dir(&directory),
        std::fs::rename(&file, &file),
        std::fs::remove_file(root.join("file/")),
        std::fs::remove_file(root.join("directory/")),
        std::fs::create_dir(root.join("file/")),
        std::fs::create_dir(root.join("directory/")),
        std::fs::rename(root.join("file/"), root.join("new")),
        std::fs::rename(&file, root.join("new/")),
        std::fs::rename(&file, root.join("directory/")),
        std::fs::rename(root.join("missing/"), root.join("new")),
        std::fs::rename(&file, root.join("missing/new/")),
        std::fs::create_dir(root.join("missing/nested/")),
    ]
    .into_iter()
    .map(|result| match result {
        Ok(()) => 0,
        Err(error) => error.raw_os_error().unwrap(),
    })
    .collect()
}

#[test]
fn owned_path_errors_match_the_host_without_mutating_it() {
    let root = std::env::temp_dir().join(format!("snare-fs-path-errors-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file"), b"data").unwrap();
    std::fs::create_dir(root.join("directory")).unwrap();
    let native = path_errors(&root);
    std::fs::remove_dir_all(&root).unwrap();
    let path = root.to_str().unwrap();
    let fs = FsBuilder::new()
        .dir(path)
        .own_prefix(path)
        .file(root.join("file").to_str().unwrap(), "data")
        .dir(root.join("directory").to_str().unwrap())
        .build();
    let modeled = Sim::builder().fs(fs).build().run(|| path_errors(&root));
    assert_eq!(modeled, native);
    assert!(!root.exists());
}

fn hard_link_path_errors(root: &Path) -> Vec<i32> {
    let file = root.join("file");
    std::fs::write(&file, b"data").unwrap();
    std::fs::hard_link(&file, root.join("alias")).unwrap();
    std::fs::create_dir(root.join("dir")).unwrap();
    ["file/", "alias/", "dir/", "missing/"]
        .into_iter()
        .flat_map(|name| {
            let target = root.join(name);
            [
                std::fs::hard_link(&file, &target),
                std::fs::rename(&file, &target),
            ]
            .map(|result| result.map_or_else(|error| error.raw_os_error().unwrap(), |_| 0))
        })
        .collect()
}

#[test]
fn hard_link_and_rename_trailing_slash_errors_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-fs-link-errors-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let native = hard_link_path_errors(&root);
    std::fs::remove_dir_all(&root).unwrap();
    let fs = FsBuilder::new().dir(&root).own_prefix(&root).build();
    let modeled = Sim::builder()
        .fs(fs)
        .build()
        .run(|| hard_link_path_errors(&root));
    assert_eq!(modeled, native);
}

#[cfg(target_os = "linux")]
fn byte_paths(root: &Path) -> (Vec<Vec<u8>>, Vec<u8>) {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let from = root.join(OsStr::from_bytes(b"\xfffile"));
    let to = root.join(OsStr::from_bytes(b"\xfefile"));
    std::fs::write(&from, b"bytes").unwrap();
    std::fs::hard_link(&from, &to).unwrap();
    let renamed = root.join(OsStr::from_bytes(b"\xfddir"));
    std::fs::create_dir(&renamed).unwrap();
    let target = renamed.join(OsStr::from_bytes(b"\xffname"));
    std::fs::rename(&from, &target).unwrap();
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().as_bytes().to_vec())
        .collect();
    names.sort();
    (names, std::fs::read(&target).unwrap())
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_paths_do_not_alias_replacement_characters_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-fs-byte-paths-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let native = byte_paths(&root);
    std::fs::remove_dir_all(&root).unwrap();
    let fs = FsBuilder::new().dir(&root).own_prefix(&root).build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| byte_paths(&root)),
        native
    );
}
