//! The processors a [`WinHost`](crate::WinHost) reports: `GetSystemInfo`'s count and mask, the
//! processor and group counts, `GetLogicalProcessorInformation(Ex)`, the NUMA node masks and the
//! per-processor `CallNtPowerInformation(ProcessorInformation)` records, all drawn from one
//! [`Topology`] so that they agree with each other and with the affinity masks and CPU sets.
//!
//! The simulated machine is one processor group, one package, one die and one NUMA node (0)
//! holding `cpus` logical processors, numbered from 0; each run of `threads_per_core` of them is
//! a core, and each core a module. Its caches are the real machine's: those of the core that
//! runs logical processor 0 are repeated for every simulated core, and those it shares with
//! other cores stand once for the whole package, so cache sizes, line sizes and levels stay
//! those of the hardware the test runs on. The per-processor power records likewise repeat the
//! real ones, renumbered.
//!
//! Record layouts, ordering and buffer conventions were measured on Windows 11 ARM64 (four
//! single-core packages): every relationship's records come in the order of `RelationAll`'s,
//! which lists each package, then each of its cores followed by its module and its own caches,
//! then the NUMA node and the group; dies are listed only when asked for by name.

use std::sync::OnceLock;

use crate::win_host::PreservedLastError;

use windows_sys::Win32::Foundation::{
    ERROR_GEN_FAILURE, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOACCESS,
};
use windows_sys::Win32::System::Power::{CallNtPowerInformation, ProcessorInformation};
use windows_sys::Win32::System::SystemInformation::{
    GetLogicalProcessorInformationEx, LOGICAL_PROCESSOR_RELATIONSHIP, RelationAll, RelationCache,
    RelationGroup, RelationNumaNode, RelationNumaNodeEx, RelationProcessorCore,
    RelationProcessorDie, RelationProcessorModule, RelationProcessorPackage, SYSTEM_INFO,
};
use windows_sys::Win32::System::Threading::{ALL_PROCESSOR_GROUPS, GetActiveProcessorCount};

/// `PROCESSOR_RELATIONSHIP.Flags` for a core running more than one logical processor
/// (`LTP_PC_SMT`, winnt.h).
const LTP_PC_SMT: u8 = 1;

/// The size of a `SYSTEM_LOGICAL_PROCESSOR_INFORMATION` on a 64-bit target: the mask, the
/// relationship, four bytes of padding the call leaves as they were, and a 16-byte union.
const LEGACY_RECORD: usize = 32;

/// The size of one `PROCESSOR_POWER_INFORMATION`: six `ULONG`s, `Number` first.
const POWER_RECORD: usize = 24;

/// The `NTSTATUS` values `CallNtPowerInformation` answers with (ntstatus.h).
const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// One of the real machine's caches: the `Level`, `Associativity`, `LineSize`, `CacheSize` and
/// `Type` bytes that `CACHE_RELATIONSHIP` and `CACHE_DESCRIPTOR` both begin with, and whether
/// it belongs to one core or is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cache {
    descriptor: [u8; 12],
    per_core: bool,
}

impl Cache {
    fn level(&self) -> u8 {
        self.descriptor[0]
    }
}

/// One record of the simulated machine, over the logical processors in `mask`.
#[derive(Clone, Copy)]
enum Record {
    /// A core, module, die or package (`PROCESSOR_RELATIONSHIP`).
    Processor {
        relationship: i32,
        mask: u64,
        flags: u8,
    },
    Cache {
        cache: Cache,
        mask: u64,
    },
    Numa {
        mask: u64,
    },
    Group,
}

impl Record {
    fn relationship(&self) -> i32 {
        match self {
            Record::Processor { relationship, .. } => *relationship,
            Record::Cache { .. } => RelationCache,
            Record::Numa { .. } => RelationNumaNode,
            Record::Group => RelationGroup,
        }
    }
}

/// The processors of a simulated Windows machine; see the module documentation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Topology {
    /// Logical processors, 1..=64.
    pub(crate) cpus: u32,
    /// Logical processors per core, 1..=`cpus`.
    pub(crate) threads_per_core: u32,
}

impl Topology {
    /// Every logical processor, as an affinity mask.
    pub(crate) fn mask(&self) -> u64 {
        u64::MAX >> (64 - self.cpus)
    }

    /// The logical processors of each core, first core first.
    fn cores(&self) -> impl Iterator<Item = u64> + use<> {
        let (cpus, threads) = (self.cpus, self.threads_per_core);
        (0..cpus).step_by(threads as usize).map(move |first| {
            let run = threads.min(cpus - first);
            (u64::MAX >> (64 - run)) << first
        })
    }

    /// `SYSTEM_CPU_SET_INFORMATION.CpuSet.LastLevelCacheIndex` for logical processor `cpu`: the
    /// first logical processor sharing its last-level cache, as the test VM numbers its per-core
    /// level 2 caches 0 to 3.
    pub(crate) fn last_level_cache_index(&self, cpu: u32) -> u8 {
        let caches = machine_caches();
        let per_core = caches
            .iter()
            .max_by_key(|cache| cache.level())
            .is_some_and(|cache| cache.per_core);
        if per_core {
            (cpu - cpu % self.threads_per_core) as u8
        } else {
            0
        }
    }

    /// The records `RelationAll` lists.
    fn all(&self) -> Vec<Record> {
        let caches = machine_caches();
        let mut records = vec![Record::Processor {
            relationship: RelationProcessorPackage,
            mask: self.mask(),
            flags: 0,
        }];
        for core in self.cores() {
            records.push(Record::Processor {
                relationship: RelationProcessorCore,
                mask: core,
                flags: if core.count_ones() > 1 { LTP_PC_SMT } else { 0 },
            });
            records.push(Record::Processor {
                relationship: RelationProcessorModule,
                mask: core,
                flags: 0,
            });
            for cache in caches.iter().filter(|cache| cache.per_core) {
                records.push(Record::Cache {
                    cache: *cache,
                    mask: core,
                });
            }
        }
        for cache in caches.iter().filter(|cache| !cache.per_core) {
            records.push(Record::Cache {
                cache: *cache,
                mask: self.mask(),
            });
        }
        records.push(Record::Numa { mask: self.mask() });
        records.push(Record::Group);
        records
    }

    /// The records `GetLogicalProcessorInformationEx(relationship)` returns, or `None` for a
    /// relationship Windows does not define.
    fn records(&self, relationship: i32) -> Option<Vec<Record>> {
        if relationship == RelationAll {
            return Some(self.all());
        }
        if relationship == RelationProcessorDie {
            return Some(vec![Record::Processor {
                relationship: RelationProcessorDie,
                mask: self.mask(),
                flags: 0,
            }]);
        }
        let wanted = if relationship == RelationNumaNodeEx {
            RelationNumaNode
        } else {
            relationship
        };
        if !(RelationProcessorCore..=RelationGroup).contains(&wanted)
            && wanted != RelationProcessorModule
        {
            return None;
        }
        let mut records = self.all();
        records.retain(|record| record.relationship() == wanted);
        Some(records)
    }

    /// One `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` record
    /// ([Microsoft Learn: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex)):
    /// `Relationship` and `Size`, then a `PROCESSOR_RELATIONSHIP` (`Flags`, `EfficiencyClass`,
    /// 20 reserved bytes, `GroupCount`, one `GROUP_AFFINITY`), a `CACHE_RELATIONSHIP` (the
    /// descriptor, 18 reserved bytes, `GroupCount`, one `GROUP_AFFINITY`), a
    /// `NUMA_NODE_RELATIONSHIP` (`NodeNumber`, 18 reserved bytes, `GroupCount`, one
    /// `GROUP_AFFINITY`) or a `GROUP_RELATIONSHIP` (`MaximumGroupCount`, `ActiveGroupCount`, 20
    /// reserved bytes, one `PROCESSOR_GROUP_INFO`). Each `GroupCount` is 1, as Windows 11
    /// reports it for every relationship, and every mask is in group 0.
    fn encode_ex(&self, record: &Record, out: &mut Vec<u8>) {
        let start = out.len();
        let size = match record {
            Record::Processor { .. } | Record::Numa { .. } => 48,
            Record::Cache { .. } => 56,
            Record::Group => 80,
        };
        out.resize(start + size, 0);
        let bytes = &mut out[start..];
        bytes[0..4].copy_from_slice(&record.relationship().to_ne_bytes());
        bytes[4..8].copy_from_slice(&(size as u32).to_ne_bytes());
        let affinity = |bytes: &mut [u8], at: usize, mask: u64| {
            bytes[at - 2..at].copy_from_slice(&1u16.to_ne_bytes());
            bytes[at..at + 8].copy_from_slice(&mask.to_ne_bytes());
        };
        match *record {
            Record::Processor { mask, flags, .. } => {
                bytes[8] = flags;
                affinity(bytes, 32, mask);
            }
            Record::Cache { cache, mask } => {
                bytes[8..20].copy_from_slice(&cache.descriptor);
                affinity(bytes, 40, mask);
            }
            Record::Numa { mask } => affinity(bytes, 32, mask),
            Record::Group => {
                bytes[8..10].copy_from_slice(&1u16.to_ne_bytes());
                bytes[10..12].copy_from_slice(&1u16.to_ne_bytes());
                bytes[32] = self.cpus as u8;
                bytes[33] = self.cpus as u8;
                bytes[72..80].copy_from_slice(&self.mask().to_ne_bytes());
            }
        }
    }

    /// One `SYSTEM_LOGICAL_PROCESSOR_INFORMATION`, for the relationships it can describe
    /// ([Microsoft Learn: SYSTEM_LOGICAL_PROCESSOR_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_logical_processor_information)):
    /// the mask, the relationship, padding (bytes 12 to 16, never written) and the union, which
    /// holds a core's `Flags`, a cache's descriptor or a node's `NodeNumber` (0), zero-filled.
    fn encode_legacy(record: &Record) -> Option<[u8; LEGACY_RECORD]> {
        let mut bytes = [0u8; LEGACY_RECORD];
        let mask = match *record {
            Record::Processor {
                relationship,
                mask,
                flags,
            } if relationship == RelationProcessorCore
                || relationship == RelationProcessorPackage =>
            {
                bytes[16] = flags;
                mask
            }
            Record::Cache { cache, mask } => {
                bytes[16..28].copy_from_slice(&cache.descriptor);
                mask
            }
            Record::Numa { mask } => mask,
            _ => return None,
        };
        bytes[0..8].copy_from_slice(&mask.to_ne_bytes());
        bytes[8..12].copy_from_slice(&record.relationship().to_ne_bytes());
        Some(bytes)
    }

    /// `GetLogicalProcessorInformation` (`relationship` `None`) or
    /// `GetLogicalProcessorInformationEx`, as measured: a null `len` is
    /// `ERROR_INVALID_PARAMETER`; an undefined relationship sets `*len` to 0 and fails with
    /// `ERROR_GEN_FAILURE`; a null buffer with a nonzero `*len` is `ERROR_NOACCESS`; a `*len`
    /// short of the records sets it to the size needed and fails with
    /// `ERROR_INSUFFICIENT_BUFFER`, after `GetLogicalProcessorInformation` has filled the whole
    /// records that fit (`Ex` writes nothing); otherwise the records are written and `*len` is
    /// their size.
    ///
    /// # Safety
    /// `len` is null or a readable and writable `DWORD`; `info` is null or valid for `*len`
    /// bytes.
    pub(crate) unsafe fn logical_processor_information(
        &self,
        relationship: Option<i32>,
        info: *mut u8,
        len: *mut u32,
    ) -> Result<(), u32> {
        if len.is_null() {
            return Err(ERROR_INVALID_PARAMETER);
        }
        // SAFETY: the caller's DWORD.
        let room = unsafe { len.read_unaligned() } as usize;
        let bytes = match relationship {
            None => {
                let records: Vec<_> = self.all().iter().filter_map(Self::encode_legacy).collect();
                records.concat()
            }
            Some(relationship) => {
                let Some(records) = self.records(relationship) else {
                    // SAFETY: as above.
                    unsafe { len.write_unaligned(0) };
                    return Err(ERROR_GEN_FAILURE);
                };
                let mut bytes = Vec::new();
                for record in &records {
                    self.encode_ex(record, &mut bytes);
                }
                bytes
            }
        };
        if info.is_null() && room != 0 {
            return Err(ERROR_NOACCESS);
        }
        // SAFETY: as above.
        unsafe { len.write_unaligned(bytes.len() as u32) };
        let (fits, result) = match (room < bytes.len(), relationship) {
            (false, _) => (bytes.len(), Ok(())),
            (true, None) => (
                room / LEGACY_RECORD * LEGACY_RECORD,
                Err(ERROR_INSUFFICIENT_BUFFER),
            ),
            (true, Some(_)) => (0, Err(ERROR_INSUFFICIENT_BUFFER)),
        };
        if fits == 0 {
            return result;
        }
        if relationship.is_some() {
            // SAFETY: `fits` bytes lie within the caller's `room`.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), info, fits) };
            return result;
        }
        for (n, record) in bytes[..fits]
            .as_chunks::<LEGACY_RECORD>()
            .0
            .iter()
            .enumerate()
        {
            let at = n * LEGACY_RECORD;
            // SAFETY: as above; the padding at 12..16 is left as it was.
            unsafe {
                std::ptr::copy_nonoverlapping(record.as_ptr(), info.add(at), 12);
                std::ptr::copy_nonoverlapping(record[16..].as_ptr(), info.add(at + 16), 16);
            }
        }
        result
    }

    /// Rewrites `dwActiveProcessorMask` and `dwNumberOfProcessors` of a `SYSTEM_INFO` the real
    /// call filled.
    ///
    /// # Safety
    /// `info` is a writable `SYSTEM_INFO`.
    pub(crate) unsafe fn write_system_info(&self, info: *mut u8) {
        let info = info.cast::<SYSTEM_INFO>();
        // SAFETY: fields of the caller's SYSTEM_INFO.
        unsafe {
            (&raw mut (*info).dwActiveProcessorMask).write_unaligned(self.mask() as usize);
            (&raw mut (*info).dwNumberOfProcessors).write_unaligned(self.cpus);
        }
    }

    /// `CallNtPowerInformation(ProcessorInformation)`: one `PROCESSOR_POWER_INFORMATION` per
    /// logical processor, each a copy of the real processor of the same index modulo the real
    /// count with `Number` set to its own. Measured on Windows 11: an input buffer, or no output
    /// buffer or an empty one, is `STATUS_INVALID_PARAMETER`; an output short of the records
    /// `STATUS_BUFFER_TOO_SMALL`, and room beyond them is left as it was.
    ///
    /// # Safety
    /// `output` is null or valid for `output_len` bytes.
    pub(crate) unsafe fn power_information(
        &self,
        input: *const u8,
        output: *mut u8,
        output_len: u32,
    ) -> u32 {
        if !input.is_null() || output.is_null() || output_len == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let need = self.cpus as usize * POWER_RECORD;
        if (output_len as usize) < need {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let real = machine_power();
        for cpu in 0..self.cpus as usize {
            let mut record = [0u8; POWER_RECORD];
            if !real.is_empty() {
                let from = cpu % real.len();
                record.copy_from_slice(&real[from]);
            }
            record[0..4].copy_from_slice(&(cpu as u32).to_ne_bytes());
            // SAFETY: `need` bytes fit in the caller's `output_len`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    record.as_ptr(),
                    output.add(cpu * POWER_RECORD),
                    POWER_RECORD,
                )
            };
        }
        STATUS_SUCCESS
    }
}

/// The real machine's `GetLogicalProcessorInformationEx(relationship)` records, empty if the
/// call fails.
fn machine_records(relationship: LOGICAL_PROCESSOR_RELATIONSHIP) -> Vec<u8> {
    let _error = PreservedLastError::new();
    snare_interpose::real(|| {
        let mut len = 0u32;
        // SAFETY: a null buffer with a zero length asks for the size.
        unsafe { GetLogicalProcessorInformationEx(relationship, std::ptr::null_mut(), &mut len) };
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` holds `len` bytes.
        let ok = unsafe {
            GetLogicalProcessorInformationEx(relationship, buf.as_mut_ptr().cast(), &mut len)
        };
        buf.truncate(len as usize);
        if ok == 0 { Vec::new() } else { buf }
    })
}

/// Each record of `buf`, a buffer of `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` records.
fn split_records(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        let size = u32::from_ne_bytes(rest.get(4..8)?.try_into().ok()?) as usize;
        if size < 8 || size > rest.len() {
            return None;
        }
        let (record, tail) = rest.split_at(size);
        rest = tail;
        Some(record)
    })
}

/// The group-0 mask among the `GROUP_AFFINITY` records `count_at` counts, which follow it.
/// A `GroupCount` of 0 is a layout from before Windows 11, with one `GROUP_AFFINITY` there.
fn group_zero_mask(record: &[u8], count_at: usize) -> Option<u64> {
    let count = u16::from_ne_bytes(record.get(count_at..count_at + 2)?.try_into().ok()?).max(1);
    (0..usize::from(count)).find_map(|n| {
        let at = count_at + 2 + n * 16;
        let affinity = record.get(at..at + 16)?;
        let group = u16::from_ne_bytes(affinity[8..10].try_into().ok()?);
        (group == 0).then(|| u64::from_ne_bytes(affinity[..8].try_into().unwrap()))
    })
}

/// The real machine's caches that serve logical processor 0 of group 0, in the order Windows
/// lists them, read once.
fn machine_caches() -> &'static [Cache] {
    static CACHES: OnceLock<Vec<Cache>> = OnceLock::new();
    CACHES.get_or_init(|| {
        let cores = machine_records(RelationProcessorCore);
        let Some(core) = split_records(&cores)
            .filter_map(|record| group_zero_mask(record, 30))
            .find(|mask| mask & 1 != 0)
        else {
            return Vec::new();
        };
        let caches = machine_records(RelationCache);
        split_records(&caches)
            .filter_map(|record| {
                let mask = group_zero_mask(record, 38)?;
                (mask & 1 != 0).then(|| Cache {
                    descriptor: record[8..20].try_into().unwrap(),
                    per_core: mask == core,
                })
            })
            .collect()
    })
}

/// The real machine's `PROCESSOR_POWER_INFORMATION` records, read on each call since their
/// current frequencies change; empty if the call fails.
fn machine_power() -> Vec<[u8; POWER_RECORD]> {
    let _error = PreservedLastError::new();
    snare_interpose::real(|| {
        // SAFETY: no arguments.
        let count = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) } as usize;
        let mut buf = vec![0u8; count * POWER_RECORD];
        // SAFETY: `buf` holds one record per processor.
        let status = unsafe {
            CallNtPowerInformation(
                ProcessorInformation,
                std::ptr::null(),
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        if status != 0 {
            return Vec::new();
        }
        buf.as_chunks::<POWER_RECORD>().0.to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cores_group_runs_of_threads() {
        let topology = Topology {
            cpus: 5,
            threads_per_core: 2,
        };
        assert_eq!(
            topology.cores().collect::<Vec<_>>(),
            [0b11, 0b1100, 0b10000]
        );
        let full = Topology {
            cpus: 64,
            threads_per_core: 1,
        };
        assert_eq!(full.mask(), u64::MAX);
        assert_eq!(full.cores().last(), Some(1 << 63));
    }
}
