#![cfg(unix)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use snare::{FsBuilder, Sim};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("snare-live-{name}-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    bytes: Vec<u8>,
    path_size: u64,
    descriptor_size: u64,
    reader_position: u64,
    writer_position: u64,
}

fn observe(path: &Path, reader: &mut File, writer: &mut File) -> Observation {
    let mut bytes = [0; 32];
    let length = reader.read_at(&mut bytes, 0).unwrap();
    Observation {
        bytes: bytes[..length].to_vec(),
        path_size: std::fs::metadata(path).unwrap().len(),
        descriptor_size: reader.metadata().unwrap().len(),
        reader_position: reader.stream_position().unwrap(),
        writer_position: writer.stream_position().unwrap(),
    }
}

fn write_visibility(path: &Path) -> Vec<Observation> {
    let mut writer = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut reader = File::open(path).unwrap();
    let mut alias = reader.try_clone().unwrap();
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ab");
    let mut result = vec![observe(path, &mut reader, &mut writer)];
    writer.write_all_at(b"XY", 0).unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    alias.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"cd");
    let mut appender = OpenOptions::new().append(true).open(path).unwrap();
    appender.write_all(b"!").unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    writer.seek(SeekFrom::Start(8)).unwrap();
    writer.write_all(b"Z").unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    drop(appender);
    drop(writer);
    assert_eq!(std::fs::read(path).unwrap(), b"XYcdef!\0Z");
    result
}

#[test]
fn independent_opens_observe_live_writes_and_metadata_os_truth() {
    let fixture = Fixture::new("writes");
    let real = write_visibility(&fixture.0);
    let fs = FsBuilder::new()
        .file(&fixture.0, b"abcdef".to_vec())
        .build();
    for deterministic in [false, true] {
        let fs = if deterministic {
            FsBuilder::new()
                .file(&fixture.0, b"abcdef".to_vec())
                .build()
        } else {
            fs.clone()
        };
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(sim.run(|| write_visibility(&fixture.0)), real);
    }
}

fn truncate_visibility(path: &Path) -> Vec<Observation> {
    let mut writer = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut reader = File::open(path).unwrap();
    reader.seek(SeekFrom::Start(4)).unwrap();
    writer.write_all_at(b"ABCDEFGH", 0).unwrap();
    let mut result = vec![observe(path, &mut reader, &mut writer)];
    let mut truncator = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    assert_eq!(reader.read(&mut [0; 2]).unwrap(), 0);
    assert_eq!(reader.stream_position().unwrap(), 4);
    truncator.write_all(b"hi").unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    writer.set_len(6).unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    let mut zeros = [1; 2];
    reader.read_exact(&mut zeros).unwrap();
    assert_eq!(zeros, [0; 2]);
    truncator.set_len(1).unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    writer.write_all_at(b"Q", 5).unwrap();
    result.push(observe(path, &mut reader, &mut writer));
    drop(writer);
    drop(truncator);
    assert_eq!(std::fs::read(path).unwrap(), b"h\0\0\0\0Q");
    result
}

#[test]
fn open_truncation_and_set_len_are_visible_without_moving_other_offsets_os_truth() {
    let fixture = Fixture::new("truncate");
    let real = truncate_visibility(&fixture.0);
    for deterministic in [false, true] {
        let fs = FsBuilder::new()
            .file(&fixture.0, b"abcdef".to_vec())
            .build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(sim.run(|| truncate_visibility(&fixture.0)), real);
    }
}

fn appenders(path: &Path) -> (usize, usize) {
    File::create(path).unwrap();
    let workers: Vec<_> = [b"AAAA\n", b"BBBB\n"]
        .into_iter()
        .map(|record| {
            let mut file = OpenOptions::new().append(true).open(path).unwrap();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    file.write_all(record).unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let bytes = std::fs::read(path).unwrap();
    let mut counts = (0, 0);
    for record in bytes.chunks(5) {
        match record {
            b"AAAA\n" => counts.0 += 1,
            b"BBBB\n" => counts.1 += 1,
            _ => panic!("interleaved append record: {record:?}"),
        }
    }
    counts
}

#[test]
fn concurrent_separate_appenders_preserve_every_record_os_truth() {
    let fixture = Fixture::new("append");
    let real = appenders(&fixture.0);
    assert_eq!(real, (200, 200));
    for deterministic in [false, true] {
        let fs = FsBuilder::new()
            .file(&fixture.0, b"abcdef".to_vec())
            .build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(sim.run(|| appenders(&fixture.0)), real);
    }
}

#[test]
fn independently_built_planes_keep_inode_contents_isolated() {
    let first = FsBuilder::new().file("/virtual/shared", "first").build();
    let second = FsBuilder::new().file("/virtual/shared", "second").build();
    let a = Sim::builder().fs(first.clone()).build();
    let b = Sim::builder().fs(second).build();
    let shared = Sim::builder().fs(first).build();
    a.run(|| {
        let mut writer = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("/virtual/shared")
            .unwrap();
        writer.write_all(b"live").unwrap();
        b.run(|| assert_eq!(std::fs::read("/virtual/shared").unwrap(), b"second"));
        shared.run(|| assert_eq!(std::fs::read("/virtual/shared").unwrap(), b"live"));
    });
}

#[test]
fn creation_requires_a_directory_parent_os_truth() {
    let directory = std::env::temp_dir().join(format!("snare-live-create-{}", std::process::id()));
    std::fs::create_dir_all(directory.join("directory")).unwrap();
    std::fs::write(directory.join("file"), b"file").unwrap();
    let probe = || {
        [
            "new",
            "directory/new",
            "missing/new",
            "missing/deeper/new",
            "file/new",
            "file/deeper/new",
        ]
        .into_iter()
        .map(|relative| {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(directory.join(relative))
                .map(|_| ())
                .map_err(|error| error.raw_os_error().unwrap())
        })
        .collect::<Vec<_>>()
    };
    let native = probe();
    let fs = FsBuilder::new()
        .own_prefix(&directory)
        .dir(&directory)
        .dir(directory.join("directory"))
        .file(directory.join("file"), "file")
        .build();
    let modeled = Sim::builder().fs(fs).build().run(probe);
    std::fs::remove_dir_all(directory).unwrap();
    assert_eq!(modeled, native);
}
