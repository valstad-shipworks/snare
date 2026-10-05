//! snare's side of fast-talker's simulator hooks. A hook answers only for
//! threads that belong to a snare state slot; fast-talker calls from any
//! other thread behave as they would without snare.

use std::io;
use std::sync::Once;
use std::time::SystemTime;

use ::fast_talker::__sim::{
    Backend, Guard, MonitorCallback, MonitorDeclined, MonitorStarted, Platform, SimHandle,
    ThreadTarget,
};
use ::fast_talker::counters::Counters;
use ::fast_talker::monitor::Config as MonitorConfig;
use ::fast_talker::options::{ProcessOption, ThreadOption};
use ::fast_talker::plan::{Drift, Plan};
use ::fast_talker::sockets::{Protocol, SocketInfo, SocketMemory, SocketOptions};
use ::fast_talker::sys_check::{Check, Finding};

use crate::netif::{SocketId, SocketKind};
use crate::os::OsSemantics;

struct SnareBackend;

static BACKEND: SnareBackend = SnareBackend;
static INSTALL: Once = Once::new();

/// Install snare's fast-talker backend. Idempotent and cheap after the
/// first call.
pub(crate) fn install() {
    INSTALL.call_once(|| {
        ::fast_talker::__sim::install(&BACKEND);
    });
}

pub(crate) fn platform_of(os: OsSemantics) -> Platform {
    match os {
        OsSemantics::Linux => Platform::Linux,
        OsSemantics::MacOs => Platform::MacOs,
        OsSemantics::Windows => Platform::Windows,
    }
}

fn in_slot() -> bool {
    crate::sched::try_slot().is_some()
}

fn socket_kind(h: SimHandle) -> io::Result<SocketKind> {
    if !in_slot() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "a snare socket used from a thread with no snare state slot",
        ));
    }
    crate::netif::socket_entry(SocketId(h.0))
        .filter(|e| !e.closed)
        .map(|e| e.kind)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such snare socket"))
}

impl Backend for SnareBackend {
    fn now(&self) -> Option<SystemTime> {
        in_slot().then(|| crate::time::SystemTime::now().into())
    }

    fn platform(&self) -> Option<Platform> {
        crate::os::try_os_semantics().map(platform_of)
    }

    fn counters_read(&self) -> Option<io::Result<Counters>> {
        in_slot().then(super::proto_counters::read)
    }

    fn socket_options_apply(&self, h: SimHandle, options: &SocketOptions) -> io::Result<()> {
        socket_kind(h)?;
        super::sockopts::apply(SocketId(h.0), options)
    }

    fn socket_memory(&self, h: SimHandle) -> io::Result<SocketMemory> {
        socket_kind(h)?;
        super::socket::socket_memory(SocketId(h.0))
    }

    fn incoming_cpu(&self, h: SimHandle) -> io::Result<Option<usize>> {
        socket_kind(h)?;
        super::nic::incoming_cpu(SocketId(h.0))
    }

    fn socket_is_stream(&self, h: SimHandle) -> io::Result<bool> {
        Ok(socket_kind(h)? == SocketKind::TcpStream)
    }

    fn socket_list(&self, protocol: Protocol) -> Option<io::Result<Vec<SocketInfo>>> {
        in_slot().then(|| super::sockopts::list(protocol))
    }

    fn plan_apply(&self, plan: &Plan) -> Option<io::Result<()>> {
        in_slot().then(|| super::plans::apply(plan))
    }

    fn plan_check(&self, plan: &Plan) -> Option<Vec<Drift>> {
        in_slot().then(|| super::plans::check(plan))
    }

    fn thread_option(
        &self,
        target: ThreadTarget,
        option: &ThreadOption,
    ) -> Option<io::Result<Guard>> {
        (in_slot() || super::rt_options::redirected())
            .then(|| super::rt_options::thread_option(target, option))
    }

    fn process_option(&self, option: &ProcessOption) -> Option<io::Result<Guard>> {
        in_slot().then(|| super::rt_options::process_option(option))
    }

    fn sys_check(&self, checks: &[Check]) -> Option<Vec<Finding>> {
        in_slot().then(|| super::host_checks::run(checks))
    }

    fn monitor_start(
        &self,
        config: MonitorConfig,
        callback: MonitorCallback,
    ) -> Result<MonitorStarted, MonitorDeclined> {
        if in_slot() {
            Ok(super::monitoring::start(config, callback))
        } else {
            Err(Box::new((config, callback)))
        }
    }
}
