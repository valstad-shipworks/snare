//! File permissions on a [`VirtualFs`](crate::VirtualFs): who the caller is, and what the mode
//! bits, ownership, the sticky bit and set-group-ID directories let it do.
//!
//! The caller is the sim the calling thread runs in. Its ids are what that sim's `geteuid` and
//! `getegid` report: root's or the unprivileged user's under a [`SimHost`](crate::SimHost), the
//! real process's without one. Whether it bypasses the checks is [`Privileges::root`], which on
//! Linux stands for the file capabilities `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`,
//! `CAP_CHOWN` and `CAP_FSETID` (capabilities(7)) and on macOS for the super-user.
//!
//! Linux's rules are fs/namei.c `generic_permission`, `may_delete` and `may_create`, fs/attr.c
//! `setattr_prepare` and `chown_ok`/`chgrp_ok`, and fs/inode.c `inode_init_owner` and
//! `file_remove_privs`; macOS's are its chmod(2), chown(2), unlink(2) and sticky(7) pages. Each
//! difference between the two was measured on Linux 7.0 (as root and as uid 1000) and macOS 26
//! (as uid 501); tests/fs_permissions.rs compares them with the host.
//!
//! [`Privileges::root`]: crate::Privileges::root

use std::ffi::c_int;
use std::sync::OnceLock;

use crate::scope::SimShared;

pub(crate) const SET_UID: u32 = 0o4000;
pub(crate) const SET_GID: u32 = 0o2000;
pub(crate) const STICKY: u32 = 0o1000;
const GROUP_EXEC: u32 = 0o010;
const ANY_EXEC: u32 = 0o111;

pub(crate) const READ: u32 = 4;
pub(crate) const WRITE: u32 = 2;
pub(crate) const EXEC: u32 = 1;

/// A node's permission bits (`07777`, the file type apart) and owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// What a node is, for the rules that tell them apart.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
    Symlink,
}

/// The caller of a file call.
#[derive(Clone, Debug)]
pub(crate) struct Credentials {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The supplementary groups, `gid` among them.
    groups: Vec<u32>,
    pub(crate) privileged: bool,
    /// The sim's umask, which macOS applies to a new symlink's mode.
    pub(crate) umask: u32,
}

impl Credentials {
    /// The caller on the calling thread: its sim's, or the real process's off a sim.
    pub(crate) fn current() -> Self {
        match crate::scope::try_here() {
            Some(shared) => Self::of(&shared),
            None => {
                let real = real_identity();
                Self {
                    privileged: real.uid == 0,
                    umask: 0o022,
                    ..real.clone()
                }
            }
        }
    }

    /// The code under test of `shared`'s sim.
    pub(crate) fn of(shared: &SimShared) -> Self {
        let privileged = shared.sys.privileges().root;
        let umask = shared.sys.umask(None);
        match shared.sys.identity() {
            Some((uid, gid)) => Self {
                uid,
                gid,
                groups: vec![gid],
                privileged,
                umask,
            },
            None => Self {
                privileged,
                umask,
                ..real_identity().clone()
            },
        }
    }

    pub(crate) fn in_group(&self, gid: u32) -> bool {
        self.groups.contains(&gid)
    }

    /// Whether `want` (a mix of [`READ`], [`WRITE`] and [`EXEC`]) is granted on a node owned as
    /// `owner`. A privileged caller is granted all but execute on a non-directory with no
    /// execute bit at all (`generic_permission`; access(2) on macOS: "only if" one is set).
    pub(crate) fn permits(&self, owner: &Owner, kind: Kind, want: u32) -> bool {
        if self.privileged {
            return want & EXEC == 0 || kind == Kind::Directory || owner.mode & ANY_EXEC != 0;
        }
        let bits = if owner.uid == self.uid {
            owner.mode >> 6
        } else if self.in_group(owner.gid) {
            owner.mode >> 3
        } else {
            owner.mode
        };
        bits & 7 & want == want
    }

    /// `EACCES` unless `want` is granted on a directory owned as `owner`.
    pub(crate) fn search(&self, owner: &Owner) -> Result<(), c_int> {
        self.check(owner, Kind::Directory, EXEC)
    }

    pub(crate) fn check(&self, owner: &Owner, kind: Kind, want: u32) -> Result<(), c_int> {
        if self.permits(owner, kind, want) {
            Ok(())
        } else {
            Err(libc::EACCES)
        }
    }

    /// Whether the caller owns the node or may act as if it did.
    pub(crate) fn owns(&self, owner: &Owner) -> bool {
        self.privileged || owner.uid == self.uid
    }

    /// May the caller remove or rename an entry owned as `victim` from a directory owned as
    /// `dir` (write and search permission granted)? A sticky directory keeps other users' entries
    /// to their owners and its own: `EPERM` otherwise, on Linux (`check_sticky`) and macOS
    /// (unlink(2), rename(2)) alike.
    pub(crate) fn may_remove(&self, dir: &Owner, victim: &Owner) -> Result<(), c_int> {
        self.check(dir, Kind::Directory, WRITE | EXEC)?;
        if dir.mode & STICKY != 0
            && !self.privileged
            && victim.uid != self.uid
            && dir.uid != self.uid
        {
            return Err(libc::EPERM);
        }
        Ok(())
    }

    /// The owner of a node the caller creates in a directory owned as `parent`, from the mode it
    /// asked for (already masked by the umask). Linux keeps the special bits of a file, the sticky
    /// bit of a directory, and a symlink is always `0777`; a new node takes the group of a
    /// set-group-ID parent, a directory its set-group-ID bit too, and a file with group execute
    /// loses set-group-ID if the caller is not in that group (`inode_init_owner`,
    /// `mode_strip_sgid`). macOS keeps only the permission bits, masks a symlink's by the umask,
    /// and gives every node its parent's group.
    pub(crate) fn create(&self, parent: &Owner, mode: u32, kind: Kind) -> Owner {
        if cfg!(target_os = "macos") {
            let mode = match kind {
                Kind::Symlink => 0o777 & !self.umask,
                _ => mode & 0o777,
            };
            return Owner {
                mode,
                uid: self.uid,
                gid: parent.gid,
            };
        }
        let inherits = parent.mode & SET_GID != 0;
        let gid = if inherits { parent.gid } else { self.gid };
        let mode = match kind {
            Kind::Symlink => 0o777,
            Kind::Directory if inherits => (mode & (0o777 | STICKY)) | SET_GID,
            Kind::Directory => mode & (0o777 | STICKY),
            Kind::File
                if inherits
                    && mode & (SET_GID | GROUP_EXEC) == SET_GID | GROUP_EXEC
                    && !self.privileged
                    && !self.in_group(gid) =>
            {
                mode & 0o7777 & !SET_GID
            }
            Kind::File => mode & 0o7777,
        };
        Owner {
            mode,
            uid: self.uid,
            gid,
        }
    }

    /// `chmod(2)` of a node owned as `owner`: `EPERM` unless the caller owns it. Bits beyond
    /// `07777` are ignored, and set-group-ID is dropped without error when the caller is not in
    /// the node's group (`setattr_prepare`; measured the same on macOS).
    pub(crate) fn chmod(&self, owner: &mut Owner, mode: u32) -> Result<(), c_int> {
        if !self.owns(owner) {
            return Err(libc::EPERM);
        }
        let mut mode = mode & 0o7777;
        if !self.privileged && !self.in_group(owner.gid) {
            mode &= !SET_GID;
        }
        owner.mode = mode;
        Ok(())
    }

    /// `chown(2)` of a node owned as `owner` to `uid` and `gid` (`u32::MAX` keeps one); whether
    /// the call marks the change time.
    ///
    /// Linux lets an unprivileged caller name only its own uid, and a group only on a node it
    /// owns and only one it belongs to (or the node's own), so a caller that does not own the
    /// node may pass only `-1` (`chown_ok`, `chgrp_ok`); every call marks the change time, and on a
    /// non-directory clears set-user-ID, and set-group-ID with group execute, even for root
    /// (`ATTR_KILL_SUID`, `ATTR_KILL_SGID`). macOS lets anyone name the ids a node already has, an
    /// owner change its group to one it belongs to; a call naming an id marks the change time and,
    /// unless the caller is the super-user, clears both bits on any node (chown(2), chmod(2)).
    pub(crate) fn chown(
        &self,
        owner: &mut Owner,
        kind: Kind,
        uid: u32,
        gid: u32,
    ) -> Result<bool, c_int> {
        let (uid, gid) = (
            (uid != u32::MAX).then_some(uid),
            (gid != u32::MAX).then_some(gid),
        );
        let mine = owner.uid == self.uid;
        if !self.privileged {
            let allowed = if cfg!(target_os = "macos") {
                uid.is_none_or(|uid| uid == owner.uid)
                    && gid.is_none_or(|gid| gid == owner.gid || (mine && self.in_group(gid)))
            } else {
                uid.is_none_or(|uid| mine && uid == owner.uid)
                    && gid.is_none_or(|gid| mine && (gid == owner.gid || self.in_group(gid)))
            };
            if !allowed {
                return Err(libc::EPERM);
            }
        }
        if let Some(uid) = uid {
            owner.uid = uid;
        }
        if let Some(gid) = gid {
            owner.gid = gid;
        }
        if cfg!(target_os = "macos") {
            let named = uid.is_some() || gid.is_some();
            if named && !self.privileged {
                owner.mode &= !(SET_UID | SET_GID);
            }
            return Ok(named);
        }
        if kind != Kind::Directory {
            owner.mode &= !SET_UID;
            if owner.mode & GROUP_EXEC != 0 {
                owner.mode &= !SET_GID;
            }
        }
        Ok(true)
    }

    /// The caller wrote a file owned as `owner` (`truncate` for a truncation): an unprivileged
    /// write takes away set-user-ID, and set-group-ID with group execute, on Linux, which does so
    /// on truncation too (`file_remove_privs`, `should_remove_suid`); macOS takes away both bits
    /// on a write but not a truncation (chmod(2); measured).
    pub(crate) fn wrote(&self, owner: &mut Owner, truncate: bool) {
        if self.privileged {
            return;
        }
        if cfg!(target_os = "macos") {
            if !truncate {
                owner.mode &= !(SET_UID | SET_GID);
            }
            return;
        }
        owner.mode &= !SET_UID;
        if owner.mode & GROUP_EXEC != 0 {
            owner.mode &= !SET_GID;
        }
    }

    /// `utimensat(2)` on a node owned as `owner`: setting either time to a given instant takes
    /// ownership (`EPERM`); setting one to the current time ownership or write permission
    /// (`EACCES`); omitting both, nothing.
    pub(crate) fn set_times(
        &self,
        owner: &Owner,
        kind: Kind,
        explicit: bool,
        now: bool,
    ) -> Result<(), c_int> {
        if self.owns(owner) {
            return Ok(());
        }
        if explicit {
            return Err(libc::EPERM);
        }
        if now {
            return self.check(owner, kind, WRITE);
        }
        Ok(())
    }
}

/// The real process's ids and groups, read once: a test process does not change them.
fn real_identity() -> &'static Credentials {
    static REAL: OnceLock<Credentials> = OnceLock::new();
    REAL.get_or_init(|| {
        snare_interpose::real(|| {
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) }.max(0);
            let mut groups = vec![0; count as usize];
            let filled = unsafe { libc::getgroups(count, groups.as_mut_ptr()) }.max(0);
            groups.truncate(filled as usize);
            if !groups.contains(&gid) {
                groups.push(gid);
            }
            Credentials {
                uid,
                gid,
                groups,
                privileged: uid == 0,
                umask: 0o022,
            }
        })
    })
}
