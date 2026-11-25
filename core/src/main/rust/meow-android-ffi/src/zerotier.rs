//! Owned ZeroTier client handle scoped to the VPN worker.

// The worker and TUN adapter consume this interface once the runtime owns a node.
#![allow(dead_code)]

use meow_overlay_policy::{routes::ManagedRoute, Prefix};
use std::{
    ffi::{c_char, c_int, c_uint, c_void, CString},
    net::Ipv4Addr,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr::NonNull,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_FRAME: usize = 1500;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct NetworkView {
    pub mac: u64,
    pub first_ipv4: u32,
    pub status: c_int,
    pub mtu: c_uint,
    pub first_ipv4_prefix: c_uint,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct Route {
    target: u32,
    via: u32,
    prefix: c_uint,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct MoonRoot {
    pub address: u64,
    pub last_receive_ms: u64,
}

#[derive(Debug)]
pub(crate) struct Frame {
    pub network: u64,
    pub from: u64,
    pub to: u64,
    pub kind: u32,
    pub data: Vec<u8>,
}

struct Callbacks {
    out: SyncSender<Frame>,
}

type ProtectFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type FrameFn = unsafe extern "C" fn(*mut c_void, u64, u64, u64, c_uint, *const u8, usize);

unsafe extern "C" {
    fn mzt_open(
        path: *const c_char,
        protect: ProtectFn,
        frame: FrameFn,
        context: *mut c_void,
        now: i64,
    ) -> *mut c_void;
    fn mzt_close(client: *mut c_void);
    fn mzt_address(client: *const c_void) -> u64;
    fn mzt_online(client: *const c_void) -> c_int;
    fn mzt_join(client: *mut c_void, network: u64) -> c_int;
    fn mzt_leave(client: *mut c_void, network: u64) -> c_int;
    fn mzt_moon_roots(
        client: *mut c_void,
        world: u64,
        roots: *mut MoonRoot,
        length: usize,
    ) -> usize;
    fn mzt_moon_id(bytes: *const u8, length: usize) -> u64;
    fn mzt_install_moon(client: *mut c_void, world: u64, bytes: *const u8, length: usize) -> c_int;
    fn mzt_orbit(client: *mut c_void, world: u64, seed: u64) -> c_int;
    fn mzt_deorbit(client: *mut c_void, world: u64) -> c_int;
    fn mzt_network(client: *const c_void, network: u64, view: *mut NetworkView) -> c_int;
    fn mzt_routes(
        client: *const c_void,
        network: u64,
        routes: *mut Route,
        capacity: usize,
    ) -> usize;
    fn mzt_step(client: *mut c_void, now: i64) -> c_int;
    fn mzt_ipv4_frame(
        client: *mut c_void,
        now: i64,
        network: u64,
        from: u64,
        to: u64,
        kind: c_uint,
        data: *const u8,
        size: usize,
    ) -> c_int;
    fn mzt_subscribe_arp(client: *mut c_void, network: u64, ipv4: u32) -> c_int;
}

unsafe extern "C" fn protect(_context: *mut c_void, fd: c_int) -> c_int {
    // Failure to exempt the fd must never fall back to an unprotected socket.
    std::panic::catch_unwind(|| {
        meow_common::socket_protector().is_some_and(|p| p.protect(fd).is_ok()) as c_int
    })
    .unwrap_or(0)
}

unsafe extern "C" fn receive(
    context: *mut c_void,
    network: u64,
    from: u64,
    to: u64,
    kind: c_uint,
    data: *const u8,
    size: usize,
) {
    if context.is_null() || data.is_null() || size == 0 || size > MAX_FRAME {
        return;
    }
    // SAFETY: the handle retains the callback box until the node closes;
    // native gives us a valid frame for the lifetime of this callback only.
    let callbacks = unsafe { &*context.cast::<Callbacks>() };
    let data = unsafe { std::slice::from_raw_parts(data, size) }.to_vec();
    // Drop full-queue traffic. A native callback must not block or reenter.
    let _ = callbacks.out.try_send(Frame {
        network,
        from,
        to,
        kind,
        data,
    });
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

pub(crate) struct Client {
    // Deliberately !Send; construct and destroy on the owning worker.
    handle: NonNull<c_void>,
    _callbacks: Box<Callbacks>,
    incoming: Receiver<Frame>,
}

pub(crate) fn moon_id(encoded: &[u8]) -> Option<u64> {
    let world = unsafe { mzt_moon_id(encoded.as_ptr(), encoded.len()) };
    (world != 0).then_some(world)
}

impl Client {
    pub fn open(path: &Path) -> Result<Self, &'static str> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid state path")?;
        let (out, incoming) = mpsc::sync_channel(128);
        let mut callbacks = Box::new(Callbacks { out });
        // SAFETY: native copies the path during creation. The callback context
        // has one stable address for the lifetime of the native handle.
        let ptr = unsafe {
            mzt_open(
                path.as_ptr(),
                protect,
                receive,
                (&mut *callbacks as *mut Callbacks).cast(),
                now(),
            )
        };
        let handle = NonNull::new(ptr).ok_or("could not open protected ZeroTier node")?;
        Ok(Self {
            handle,
            _callbacks: callbacks,
            incoming,
        })
    }

    pub fn address(&self) -> u64 {
        unsafe { mzt_address(self.handle.as_ptr()) }
    }
    pub fn online(&self) -> bool {
        unsafe { mzt_online(self.handle.as_ptr()) != 0 }
    }
    pub fn join(&mut self, network: u64) -> i32 {
        unsafe { mzt_join(self.handle.as_ptr(), network) }
    }
    pub fn leave(&mut self, network: u64) -> i32 {
        unsafe { mzt_leave(self.handle.as_ptr(), network) }
    }
    pub fn moon_roots(&mut self, world: u64) -> Vec<MoonRoot> {
        let mut roots = [MoonRoot::default(); 4];
        let count =
            unsafe { mzt_moon_roots(self.handle.as_ptr(), world, roots.as_mut_ptr(), roots.len()) };
        roots[..count.min(roots.len())].to_vec()
    }
    pub fn install_moon(&mut self, world: u64, encoded: &[u8]) -> bool {
        unsafe {
            mzt_install_moon(self.handle.as_ptr(), world, encoded.as_ptr(), encoded.len()) == 0
        }
    }
    pub fn orbit(&mut self, world: u64, seed: u64) -> i32 {
        unsafe { mzt_orbit(self.handle.as_ptr(), world, seed) }
    }
    pub fn deorbit(&mut self, world: u64) -> i32 {
        unsafe { mzt_deorbit(self.handle.as_ptr(), world) }
    }
    pub fn network(&self, network: u64) -> Option<NetworkView> {
        let mut view = NetworkView::default();
        (unsafe { mzt_network(self.handle.as_ptr(), network, &mut view) } == 1).then_some(view)
    }
    pub fn routes(&self, network: u64) -> Vec<ManagedRoute> {
        let mut routes = [Route::default(); 128];
        let len = unsafe {
            mzt_routes(
                self.handle.as_ptr(),
                network,
                routes.as_mut_ptr(),
                routes.len(),
            )
        };
        routes
            .iter()
            .take(len)
            .filter_map(|r| {
                Some(ManagedRoute {
                    target: Prefix::new(Ipv4Addr::from(r.target), r.prefix.try_into().ok()?)?,
                    via: (r.via != 0).then(|| Ipv4Addr::from(r.via)),
                })
            })
            .collect()
    }
    pub fn step(&mut self) -> i32 {
        unsafe { mzt_step(self.handle.as_ptr(), now()) }
    }
    pub fn send(&mut self, frame: &Frame) -> i32 {
        unsafe {
            mzt_ipv4_frame(
                self.handle.as_ptr(),
                now(),
                frame.network,
                frame.from,
                frame.to,
                frame.kind,
                frame.data.as_ptr(),
                frame.data.len(),
            )
        }
    }
    pub fn subscribe_arp(&mut self, network: u64, ipv4: u32) -> i32 {
        unsafe { mzt_subscribe_arp(self.handle.as_ptr(), network, ipv4) }
    }
    pub fn receive(&self) -> Result<Frame, TryRecvError> {
        self.incoming.try_recv()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: one owner releases before Rust drops the callback context.
        unsafe { mzt_close(self.handle.as_ptr()) };
    }
}
