//! Vectored I/O against the host: the same `readv`/`writev`/`preadv`/`pwritev` calls on a stream
//! socketpair, a datagram socketpair and a file, run on the real OS and in a sim (its socketpairs
//! and a `VirtualFs` file), must return the same counts, errnos and bytes: iovec counts of zero
//! and past `UIO_MAXIOV`, a stream's gather and scatter, a datagram's boundaries and truncation,
//! positioned calls on a socket, and a file's offset.
#![cfg(unix)]

use std::ffi::c_int;

use snare::{FsBuilder, Sim};

/// One call's return, its errno when it failed, and the bytes it read.
type Seen = (&'static str, isize, c_int, Vec<u8>);

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn iovec(bytes: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    }
}

fn seen(label: &'static str, result: isize, read: Vec<u8>) -> Seen {
    (label, result, if result < 0 { errno() } else { 0 }, read)
}

/// `readv` (or `preadv` at `offset`) into buffers of `sizes` bytes: the return, and the bytes of
/// each buffer that were filled, joined with `|`.
fn scatter(label: &'static str, fd: c_int, sizes: &[usize], offset: Option<i64>) -> Seen {
    let mut buffers: Vec<Vec<u8>> = sizes.iter().map(|&size| vec![0u8; size]).collect();
    let parts: Vec<libc::iovec> = buffers
        .iter_mut()
        .map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        })
        .collect();
    let result = unsafe {
        match offset {
            Some(offset) => libc::preadv(fd, parts.as_ptr(), parts.len() as c_int, offset),
            None => libc::readv(fd, parts.as_ptr(), parts.len() as c_int),
        }
    };
    let mut left = result.max(0) as usize;
    let mut read = Vec::new();
    for buf in &buffers {
        let take = left.min(buf.len());
        read.extend_from_slice(&buf[..take]);
        read.push(b'|');
        left -= take;
    }
    seen(label, result, read)
}

fn gather(label: &'static str, fd: c_int, parts: &[&[u8]], offset: Option<i64>) -> Seen {
    let parts: Vec<libc::iovec> = parts.iter().map(|part| iovec(part)).collect();
    let result = unsafe {
        match offset {
            Some(offset) => libc::pwritev(fd, parts.as_ptr(), parts.len() as c_int, offset),
            None => libc::writev(fd, parts.as_ptr(), parts.len() as c_int),
        }
    };
    seen(label, result, Vec::new())
}

fn pair(ty: c_int) -> [c_int; 2] {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, ty, 0, fds.as_mut_ptr()) },
        0
    );
    fds
}

fn observe(path: &std::ffi::CStr) -> Vec<Seen> {
    let mut out = Vec::new();
    let [a, b] = pair(libc::SOCK_STREAM);
    out.push(gather("stream writev", a, &[b"ab", b"", b"cde"], None));
    out.push(scatter("stream readv", b, &[2, 1, 10], None));
    out.push(gather("stream writev of none", a, &[], None));
    let many = vec![iovec(b"x"); 1025];
    out.push(seen(
        "stream writev past UIO_MAXIOV",
        unsafe { libc::writev(a, many.as_ptr(), 1025) },
        Vec::new(),
    ));
    out.push(gather("stream pwritev", a, &[b"z"], Some(0)));
    out.push(scatter("stream preadv", b, &[4], Some(0)));
    unsafe {
        libc::close(a);
        libc::close(b);
    }

    let [c, d] = pair(libc::SOCK_DGRAM);
    out.push(gather("dgram writev", c, &[b"one", b"two"], None));
    out.push(gather("dgram writev again", c, &[b"xy", b"z"], None));
    out.push(scatter("dgram readv", d, &[16], None));
    out.push(scatter("dgram readv truncated", d, &[1, 1], None));
    unsafe { libc::fcntl(d, libc::F_SETFL, libc::O_NONBLOCK) };
    out.push(scatter("dgram readv after truncation", d, &[16], None));
    unsafe {
        libc::close(c);
        libc::close(d);
    }

    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0, "open: {}", errno());
    out.push(gather("file writev", fd, &[b"hello", b" ", b"world"], None));
    out.push(gather("file pwritev", fd, &[b"HE", b"LL"], Some(0)));
    out.push(seen(
        "file offset",
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } as isize,
        Vec::new(),
    ));
    out.push(scatter("file preadv", fd, &[3, 20], Some(2)));
    out.push(scatter("file readv at end", fd, &[4], None));
    out.push(scatter("file preadv past end", fd, &[4], Some(100)));
    out.push(scatter("file preadv negative", fd, &[4], Some(-1)));
    out.push(gather("file pwritev past end", fd, &[b"!"], Some(13)));
    out.push(scatter("file preadv of hole", fd, &[8], Some(9)));
    unsafe {
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
    out
}

#[test]
fn vectored_io_matches_the_host() {
    let dir = std::env::temp_dir().join(format!("snare-vectored-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path =
        std::ffi::CString::new(dir.join("file").into_os_string().into_encoded_bytes()).unwrap();
    let real = snare::real(|| observe(&path));
    let fs = FsBuilder::new().dir(dir.to_str().unwrap()).build();
    let simulated = Sim::builder().fs(fs).build().run(|| observe(&path));
    std::fs::remove_dir_all(&dir).ok();
    for (real, simulated) in real.iter().zip(&simulated) {
        assert_eq!(simulated, real);
    }
    assert_eq!(simulated.len(), real.len());
}
