use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::{CompletionCall, CompletionPost, NetResult};
use windows_sys::Win32::Foundation::GetLastError;

use super::{Sock, WinNet};
use crate::readiness::{Deadline, WakeKey, WakeKeys, readiness};
use crate::sockets::SockRec;

#[derive(Default)]
pub(super) struct State {
    ports: HashMap<usize, Arc<Port>>,
    files: HashMap<usize, (Arc<Port>, usize)>,
    next_id: u64,
    requests: Vec<Request>,
}

struct Port {
    handle: usize,
    id: u64,
    post: CompletionPost,
    closed: AtomicBool,
    external: AtomicBool,
    modeled: AtomicBool,
    gate: Mutex<()>,
    generation: AtomicU64,
}

struct Request {
    file: usize,
    port: Arc<Port>,
    key: usize,
    status: usize,
    output: usize,
    context: usize,
    mask: u32,
    rec: Arc<SockRec>,
}

#[repr(C)]
struct Status {
    status: isize,
    information: usize,
}
#[repr(C)]
struct PollHandle {
    handle: usize,
    events: u32,
    status: i32,
}
#[repr(C)]
struct PollInfo {
    timeout: i64,
    count: u32,
    exclusive: u32,
    handle: PollHandle,
}

impl Request {
    unsafe fn complete(&self, events: u32, status: i32) {
        unsafe {
            let information = if status < 0 {
                std::mem::offset_of!(PollInfo, handle)
            } else {
                std::mem::size_of::<PollInfo>()
            };
            if status >= 0 {
                let info = &mut *(self.output as *mut PollInfo);
                info.handle.events = events;
                info.handle.status = 0;
            }
            *(self.status as *mut Status) = Status {
                status: status as isize,
                information,
            };
            (self.port.post)(
                self.port.handle as *mut u8,
                self.key as *mut u8,
                self.context as *mut u8,
                status,
                information,
            );
        }
    }
}

impl WinNet {
    fn afd_events(&self, rec: &SockRec) -> u32 {
        let socks = self.socks.lock().unwrap();
        let Some(sock) = socks.values().find(|sock| sock.rec().id == rec.id) else {
            return 32;
        };
        match sock {
            Sock::Fresh { rec, .. } if rec.peek_socket_error().is_some() => 256,
            Sock::Fresh { .. } | Sock::Connecting { .. } => 0,
            Sock::Stream { conn, end, rec, .. } => {
                let read = conn.read_pipe(*end);
                let write = conn.write_pipe(*end);
                if read.is_reset() || write.is_reset() || rec.peek_socket_error().is_some() {
                    return 16;
                }
                u32::from(read.readable_or_closed())
                    | (u32::from(write.writable()) * 4)
                    | (u32::from(read.read_eof()) * 8)
            }
            Sock::Dgram { queue, rec, .. } => {
                u32::from(queue.has(|_| true) || rec.peek_error().is_some()) | 4
            }
            Sock::Listener { state, .. } => {
                u32::from(!state.pending.lock().unwrap().is_empty()) * 128
            }
        }
    }

    fn completion_refresh(&self, port: &Port) {
        self.advance_connecting(None);
        let mut state = self.completions.lock().unwrap();
        let mut index = 0;
        while index < state.requests.len() {
            let request = &state.requests[index];
            let events = if request.port.id == port.id {
                self.afd_events(&request.rec) & request.mask
            } else {
                0
            };
            if events != 0 {
                let request = state.requests.remove(index);
                unsafe {
                    request.complete(events, 0);
                }
            } else {
                index += 1;
            }
        }
    }

    fn completion_interests(&self, port: &Port) -> (WakeKeys, bool) {
        let mut keys = WakeKeys::default();
        keys.push(WakeKey::CompletionPort(port.id));
        let state = self.completions.lock().unwrap();
        let mut timed = false;
        for request in &state.requests {
            if request.port.id == port.id {
                keys.push(request.rec.wake_key());
                timed |= request.rec.pending_time();
                timed |= self.socks.lock().unwrap().values().any(|sock| {
                    sock.rec().id == request.rec.id && matches!(sock, Sock::Connecting { .. })
                });
            }
        }
        (keys, timed)
    }

    fn completion_due(&self, port: &Port) -> bool {
        let state = self.completions.lock().unwrap();
        state.requests.iter().any(|request| request.port.id == port.id && (self.afd_events(&request.rec) & request.mask != 0 || self.socks.lock().unwrap().iter().any(|(fd, sock)| sock.rec().id == request.rec.id && matches!(sock, Sock::Connecting { attempt, .. } if attempt.lock().unwrap().due()) && *fd >= 0)))
    }
}

pub(super) unsafe fn call(net: &WinNet, call: CompletionCall) -> Option<NetResult> {
    match call {
        CompletionCall::Duplicate { handle } => {
            let state = net.completions.lock().unwrap();
            let port = state.ports.get(&handle)?;
            (!port.external.load(Ordering::Acquire)).then_some(NetResult::Err(50))
        }
        CompletionCall::Associate { port, afd } => {
            let state = net.completions.lock().unwrap();
            let port = state.ports.get(&port)?;
            Some(if !afd && port.modeled.load(Ordering::Acquire) {
                NetResult::Err(50)
            } else {
                NetResult::Ok(0)
            })
        }
        CompletionCall::Register {
            file,
            port,
            key,
            post,
            afd,
        } => {
            let mut state = net.completions.lock().unwrap();
            if !state.ports.contains_key(&port) {
                state.next_id += 1;
                let description = Arc::new(Port {
                    handle: port,
                    id: state.next_id,
                    post,
                    closed: AtomicBool::new(false),
                    external: AtomicBool::new(false),
                    modeled: AtomicBool::new(false),
                    gate: Mutex::new(()),
                    generation: AtomicU64::new(0),
                });
                state.ports.insert(port, description);
            }
            let description = state.ports[&port].clone();
            if file != usize::MAX {
                if !afd {
                    description.external.store(true, Ordering::Release);
                }
                state.files.entry(file).or_insert((description, key));
            }
            Some(NetResult::Ok(0))
        }
        CompletionCall::Notify { port } => {
            let port = net.completions.lock().unwrap().ports.get(&port)?.clone();
            net.regs
                .shared
                .bump_keys(&[WakeKey::CompletionPort(port.id)]);
            Some(NetResult::Ok(0))
        }
        CompletionCall::Poll {
            file,
            status,
            context,
            input,
            input_len,
            output,
            output_len,
        } => {
            if input.is_null()
                || status.is_null()
                || output.is_null()
                || input_len < std::mem::size_of::<PollInfo>() as u32
                || output_len < std::mem::size_of::<PollInfo>() as u32
            {
                return Some(NetResult::Ok(0xc000000d_u32 as i64));
            }
            let info = unsafe { &*input.cast::<PollInfo>() };
            if info.count != 1 {
                return Some(NetResult::Ok(0xc00000bb_u32 as i64));
            }
            let rec = net.rec(info.handle.handle as i32);
            let mut state = net.completions.lock().unwrap();
            let (port, key) = state.files.get(&file)?.clone();
            let Some(rec) = rec else {
                if port.modeled.load(Ordering::Acquire) {
                    return Some(NetResult::Ok(0xc00000bb_u32 as i64));
                }
                port.external.store(true, Ordering::Release);
                return None;
            };
            if info.timeout != i64::MAX
                || info.exclusive != 0
                || port.external.load(Ordering::Acquire)
            {
                return Some(NetResult::Ok(0xc00000bb_u32 as i64));
            }
            if port.closed.load(Ordering::Acquire) {
                return Some(NetResult::Ok(0xc0000008_u32 as i64));
            }
            if state
                .requests
                .iter()
                .any(|request| request.status == status as usize)
            {
                return Some(NetResult::Ok(0xc000000d_u32 as i64));
            }
            unsafe {
                *(status.cast::<Status>()) = Status {
                    status: 0x103,
                    information: 0,
                };
            }
            port.modeled.store(true, Ordering::Release);
            let request = Request {
                file,
                port: port.clone(),
                key,
                status: status as usize,
                output: output as usize,
                context,
                mask: info.handle.events,
                rec,
            };
            let events = net.afd_events(&request.rec) & request.mask;
            let completed = events != 0;
            if completed {
                unsafe { request.complete(events, 0) };
            } else {
                state.requests.push(request);
            }
            port.generation.fetch_add(1, Ordering::Release);
            drop(state);
            net.regs
                .shared
                .bump_keys(&[WakeKey::CompletionPort(port.id)]);
            Some(NetResult::Ok(if completed { 0 } else { 0x103 }))
        }
        CompletionCall::Cancel {
            file,
            status,
            result,
        } => {
            let mut state = net.completions.lock().unwrap();
            if !state.files.contains_key(&file) {
                return None;
            }
            let port = state.files[&file].0.clone();
            let mut found = false;
            let mut index = 0;
            while index < state.requests.len() {
                if state.requests[index].file == file
                    && (status.is_null() || state.requests[index].status == status as usize)
                {
                    let request = state.requests.remove(index);
                    unsafe {
                        request.complete(0, 0xc0000120_u32 as i32);
                    }
                    found = true;
                } else {
                    index += 1;
                }
            }
            if !found {
                return None;
            }
            if !result.is_null() {
                unsafe {
                    *result.cast::<Status>() = Status {
                        status: 0,
                        information: 0,
                    };
                }
            }
            drop(state);
            if found {
                port.generation.fetch_add(1, Ordering::Release);
                net.regs
                    .shared
                    .bump_keys(&[WakeKey::CompletionPort(port.id)]);
            }
            Some(NetResult::Ok(if found { 0 } else { 0xc0000225_u32 as i64 }))
        }
        CompletionCall::Close { handle, native } => {
            let mut state = net.completions.lock().unwrap();
            let description = state.ports.get(&handle).cloned();
            let gate = description.as_ref().map(|port| port.gate.lock().unwrap());
            let result = unsafe { native(handle as *mut u8) };
            if result == 0 {
                return Some(NetResult::Err(unsafe { GetLastError() } as i32));
            }
            let port = state.ports.remove(&handle);
            if let Some(port) = &port {
                port.closed.store(true, Ordering::Release);
            }
            let file = state.files.remove(&handle);
            let mut index = 0;
            while index < state.requests.len() {
                if state.requests[index].file == handle
                    || port
                        .as_ref()
                        .is_some_and(|port| port.id == state.requests[index].port.id)
                {
                    let request = state.requests.remove(index);
                    if !request.port.closed.load(Ordering::Acquire) {
                        unsafe {
                            request.complete(0, 0xc0000120_u32 as i32);
                        }
                    }
                } else {
                    index += 1;
                }
            }
            let key = port
                .or_else(|| file.map(|(port, _)| port))
                .map(|port| WakeKey::CompletionPort(port.id));
            drop(gate);
            drop(state);
            if let Some(key) = key {
                net.regs.shared.bump_keys(&[key]);
            }
            Some(NetResult::Ok(result as i64))
        }
        CompletionCall::Get {
            port,
            entries,
            count,
            removed,
            timeout,
            alertable,
            query,
        } => {
            let port = net.completions.lock().unwrap().ports.get(&port)?.clone();
            if port.external.load(Ordering::Acquire) {
                return None;
            }
            if alertable != 0 {
                return Some(NetResult::Err(50));
            }
            let deadline = (timeout != u32::MAX)
                .then(|| Deadline::timeout(Duration::from_millis(timeout as u64)));
            let observed = Cell::new(None);
            let probe = || {
                if observed.get().is_some() {
                    return true;
                }
                let _gate = port.gate.lock().unwrap();
                if port.closed.load(Ordering::Acquire) {
                    observed.set(Some(Err(735)));
                    return true;
                }
                let result =
                    unsafe { query(port.handle as *mut u8, entries, count, removed, 0, 0) };
                if result != 0 {
                    observed.set(Some(Ok(result as i64)));
                    true
                } else {
                    let error = unsafe { GetLastError() };
                    if error != 258 {
                        observed.set(Some(Err(error as i32)));
                        true
                    } else {
                        false
                    }
                }
            };
            loop {
                net.completion_refresh(&port);
                if probe() {
                    return observed.get().map(|result| match result {
                        Ok(value) => NetResult::Ok(value),
                        Err(error) => NetResult::Err(error),
                    });
                }
                if timeout == 0 || deadline.is_some_and(|deadline| deadline.passed()) {
                    return Some(NetResult::Err(258));
                }
                let generation = port.generation.load(Ordering::Acquire);
                let (keys, _) = net.completion_interests(&port);
                if !readiness().wait_until_on(
                    "IOCP",
                    deadline,
                    keys.as_slice(),
                    || net.completion_interests(&port).1,
                    || {
                        probe()
                            || port.generation.load(Ordering::Acquire) != generation
                            || net.completion_due(&port)
                    },
                ) {
                    return Some(NetResult::Err(258));
                }
                if observed.get().is_some() {
                    return observed.get().map(|result| match result {
                        Ok(value) => NetResult::Ok(value),
                        Err(error) => NetResult::Err(error),
                    });
                }
            }
        }
    }
}
