#![doc = "Dynamic bindings to the vendored `WinDivert` 2.2 user-mode library."]

pub(crate) mod divert;
pub(crate) mod flow;
pub(crate) mod packet;

use std::{
    ffi::CString,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    System::LibraryLoader::{GetProcAddress, LoadLibraryW},
};

use crate::ClientError;

/// Layer identifiers from `WINDIVERT_LAYER`.
pub(crate) const LAYER_NETWORK: u32 = 0;
pub(crate) const LAYER_FLOW: u32 = 2;
pub(crate) const LAYER_SOCKET: u32 = 3;

/// Event identifiers from `WINDIVERT_EVENT`.
pub(crate) const EVENT_FLOW_ESTABLISHED: u32 = 1;
pub(crate) const EVENT_FLOW_DELETED: u32 = 2;
pub(crate) const EVENT_SOCKET_CONNECT: u32 = 4;
pub(crate) const EVENT_SOCKET_CLOSE: u32 = 7;

/// Handle flags from `WINDIVERT_FLAG_*`.
pub(crate) const FLAG_SNIFF: u64 = 0x0001;
pub(crate) const FLAG_RECV_ONLY: u64 = 0x0004;

/// `WINDIVERT_SHUTDOWN_BOTH`.
const SHUTDOWN_BOTH: u32 = 0x3;

/// The largest packet `WinDivert` will hand back, from `WINDIVERT_MTU_MAX`.
pub(crate) const MTU_MAX: usize = 40 + 0xFFFF;

/// The most packets one `WinDivertRecvEx` or `WinDivertSendEx` can carry, from
/// `WINDIVERT_BATCH_MAX`.
pub(crate) const BATCH_MAX: usize = 0xFF;

/// `WINDIVERT_PARAM_*`.
const PARAM_QUEUE_LENGTH: u32 = 0;
const PARAM_QUEUE_TIME: u32 = 1;
const PARAM_QUEUE_SIZE: u32 = 2;

/// The queue the driver fills while user mode is busy elsewhere.
///
/// The defaults — 4096 packets, 4MB, 2s — suit a tool that inspects a trickle.
/// A split tunnel sits on the path of every connection the machine makes, and
/// a burst that outruns the capture loop is not held politely: the driver
/// discards the overflow, senders see loss they have no reason to expect, and
/// TCP answers by halving its window. That is the stall users report as "the
/// VPN lags". The maxima cost pinned kernel memory only while the queue is
/// actually full, which is precisely when it is worth spending.
const QUEUE_LENGTH: u64 = 16_384;
const QUEUE_SIZE: u64 = 33_554_432;
/// Deliberately below the 16s maximum: a packet held longer than this is one
/// the sender has already retransmitted, so delivering it late only spends
/// bandwidth on a duplicate.
const QUEUE_TIME: u64 = 4_000;

type OpenFn = unsafe extern "system" fn(*const i8, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "system" fn(HANDLE, *const u8, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "system" fn(HANDLE, u32) -> i32;
type CloseFn = unsafe extern "system" fn(HANDLE) -> i32;
type CalcChecksumsFn = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;
type CompileFilterFn =
    unsafe extern "system" fn(*const i8, u32, *mut i8, u32, *mut *const i8, *mut u32) -> i32;
type RecvExFn = unsafe extern "system" fn(
    HANDLE,
    *mut u8,
    u32,
    *mut u32,
    u64,
    *mut Address,
    *mut u32,
    *mut core::ffi::c_void,
) -> i32;
type SendExFn = unsafe extern "system" fn(
    HANDLE,
    *const u8,
    u32,
    *mut u32,
    u64,
    *const Address,
    u32,
    *mut core::ffi::c_void,
) -> i32;
type SetParamFn = unsafe extern "system" fn(HANDLE, u32, u64) -> i32;
/// Every header output is passed as null; only the trailing `ppNext` and
/// `pNextLen` pair is read.
type ParsePacketFn = unsafe extern "system" fn(
    *const u8,
    u32,
    *mut *const (),
    *mut *const (),
    *mut u8,
    *mut *const (),
    *mut *const (),
    *mut *const (),
    *mut *const (),
    *mut *const (),
    *mut u32,
    *mut *const u8,
    *mut u32,
) -> i32;

/// A `WinDivert` address, mirroring `WINDIVERT_ADDRESS`.
///
/// The C definition packs `Layer`, `Event` and eight one-bit properties into a
/// single `UINT32` bitfield. Rust has no bitfields, so the word is stored raw
/// and read through the accessors below. MSVC allocates bitfields from the
/// least significant bit upwards, which is what the shifts assume.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Address {
    pub(crate) timestamp: i64,
    bitfield: u32,
    _reserved: u32,
    /// The `WINDIVERT_DATA_*` union. Read it with [`Address::flow`] or
    /// [`Address::network`], which check the layer first.
    payload: [u8; 64],
}

/// `WINDIVERT_DATA_FLOW`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct FlowData {
    pub(crate) endpoint_id: u64,
    pub(crate) parent_endpoint_id: u64,
    pub(crate) process_id: u32,
    pub(crate) local_addr: [u32; 4],
    pub(crate) remote_addr: [u32; 4],
    pub(crate) local_port: u16,
    pub(crate) remote_port: u16,
    pub(crate) protocol: u8,
}

/// `WINDIVERT_DATA_NETWORK`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NetworkData {
    pub(crate) if_idx: u32,
    pub(crate) sub_if_idx: u32,
}

impl Address {
    pub(crate) const fn zeroed() -> Self {
        Self {
            timestamp: 0,
            bitfield: 0,
            _reserved: 0,
            payload: [0; 64],
        }
    }

    /// Describes an inbound network packet arriving on `interface_index`.
    ///
    /// Injecting a packet the stack never saw needs an address built by hand.
    /// `LAYER_NETWORK` and the packet event are both zero, and leaving the
    /// outbound bit clear is what marks the packet as arriving rather than
    /// leaving. `WinDivert` delivers it to whichever socket is bound to the
    /// destination, which is how translated tunnel traffic reaches the
    /// application that asked for it.
    pub(crate) fn for_inbound(interface_index: u32, sub_interface_index: u32) -> Self {
        let mut address = Self::zeroed();
        address.bitfield = LAYER_NETWORK;
        let network = NetworkData {
            if_idx: interface_index,
            sub_if_idx: sub_interface_index,
        };
        // SAFETY: `payload` is 64 bytes and `NetworkData` is two `u32`s, so the
        // write stays well inside the union.
        unsafe {
            ptr::write_unaligned(address.payload.as_mut_ptr().cast::<NetworkData>(), network);
        }
        address
    }

    pub(crate) const fn layer(&self) -> u32 {
        self.bitfield & 0xFF
    }

    pub(crate) const fn event(&self) -> u32 {
        (self.bitfield >> 8) & 0xFF
    }

    pub(crate) const fn ipv6(&self) -> bool {
        (self.bitfield >> 20) & 1 == 1
    }

    /// Reinterprets the union as flow data.
    ///
    /// The socket layer shares this member's layout exactly, and both are read
    /// the same way. Any other layer returns `None`, so a mismatched one cannot
    /// be read as the wrong union member.
    pub(crate) fn flow(&self) -> Option<FlowData> {
        (self.layer() == LAYER_FLOW || self.layer() == LAYER_SOCKET).then(|| {
            // SAFETY: `FlowData` is 64 bytes of plain integers with no
            // padding requirements beyond 8-byte alignment, `payload` is 64
            // bytes inside a structure aligned to 8, and the layer check above
            // establishes that WinDivert wrote this union member.
            unsafe { ptr::read_unaligned(self.payload.as_ptr().cast::<FlowData>()) }
        })
    }
}

/// The loaded `WinDivert.dll` and the entry points `MouseVPN` uses.
///
/// The library is resolved next to the running executable rather than embedded
/// and extracted like `wintun.dll`. `WinDivert` is used under the LGPL, which
/// requires that a user be able to drop in their own build; a copy rewritten
/// from the executable on every launch would defeat that. It also lets
/// `WinDivert.dll` find `WinDivert64.sys` beside itself, which is how it
/// installs and removes the driver service on its own.
pub(crate) struct Library {
    // Kept as a `usize` so the library stays `Send`: handles are shared with
    // the flow watcher and packet threads.
    _module: usize,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    calc_checksums: CalcChecksumsFn,
    compile_filter: CompileFilterFn,
    recv_ex: RecvExFn,
    send_ex: SendExFn,
    set_param: SetParamFn,
    parse_packet: ParsePacketFn,
}

// SAFETY: the module handle is only held to keep the DLL loaded, and every
// entry point is a plain function pointer into it. WinDivert's own handles
// carry the per-handle state and are documented as usable from any thread.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Library {
    /// Loads `WinDivert.dll` from the directory holding the current executable.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the DLL is missing, cannot be
    /// loaded, or does not export the expected `WinDivert` 2.2 entry points.
    pub(crate) fn load() -> Result<Arc<Self>, ClientError> {
        let path = library_path()?;
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(ClientError::Platform(format!(
                "failed to load {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let module_address = module as usize;

        // SAFETY: each name is a NUL-terminated literal, and the signatures
        // match `windivert.h` for the version pinned in `vendor/windivert`.
        // `resolve` fails rather than returning a null pointer, so no
        // transmute below can produce a dangling function.
        let library = unsafe {
            Self {
                _module: module_address,
                open: std::mem::transmute::<*const (), OpenFn>(resolve(module, c"WinDivertOpen")?),
                recv: std::mem::transmute::<*const (), RecvFn>(resolve(module, c"WinDivertRecv")?),
                send: std::mem::transmute::<*const (), SendFn>(resolve(module, c"WinDivertSend")?),
                shutdown: std::mem::transmute::<*const (), ShutdownFn>(resolve(
                    module,
                    c"WinDivertShutdown",
                )?),
                close: std::mem::transmute::<*const (), CloseFn>(resolve(
                    module,
                    c"WinDivertClose",
                )?),
                calc_checksums: std::mem::transmute::<*const (), CalcChecksumsFn>(resolve(
                    module,
                    c"WinDivertHelperCalcChecksums",
                )?),
                compile_filter: std::mem::transmute::<*const (), CompileFilterFn>(resolve(
                    module,
                    c"WinDivertHelperCompileFilter",
                )?),
                recv_ex: std::mem::transmute::<*const (), RecvExFn>(resolve(
                    module,
                    c"WinDivertRecvEx",
                )?),
                send_ex: std::mem::transmute::<*const (), SendExFn>(resolve(
                    module,
                    c"WinDivertSendEx",
                )?),
                set_param: std::mem::transmute::<*const (), SetParamFn>(resolve(
                    module,
                    c"WinDivertSetParam",
                )?),
                parse_packet: std::mem::transmute::<*const (), ParsePacketFn>(resolve(
                    module,
                    c"WinDivertHelperParsePacket",
                )?),
            }
        };
        Ok(Arc::new(library))
    }

    /// Compiles `filter` without opening a handle, to explain a rejection.
    ///
    /// `WinDivertOpen` reports a bad filter as a bare `ERROR_INVALID_PARAMETER`,
    /// which says nothing about what is wrong with it. The filter compiler
    /// reports the reason and the offset it failed at, and needs neither the
    /// driver nor elevation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] naming the offending position when the
    /// filter does not compile.
    pub(crate) fn check_filter(&self, filter: &str, layer: u32) -> Result<(), ClientError> {
        let text = CString::new(filter).map_err(|_| {
            ClientError::Platform("WinDivert filter contained an interior NUL".to_owned())
        })?;
        let mut reason: *const i8 = ptr::null();
        let mut position = 0_u32;
        // SAFETY: `text` outlives the call, and passing a null object buffer
        // with zero length asks for validation only.
        let compiled = unsafe {
            (self.compile_filter)(
                text.as_ptr(),
                layer,
                ptr::null_mut(),
                0,
                &raw mut reason,
                &raw mut position,
            )
        };
        if compiled != 0 {
            return Ok(());
        }
        let detail = if reason.is_null() {
            "no reason reported".to_owned()
        } else {
            // SAFETY: on failure WinDivert points this at a static string.
            unsafe { std::ffi::CStr::from_ptr(reason) }
                .to_string_lossy()
                .into_owned()
        };
        Err(ClientError::Platform(format!(
            "WinDivert rejected the capture filter at position {position}: {detail}; filter was: {filter}"
        )))
    }

    /// Opens a `WinDivert` handle for `filter` on `layer`.
    ///
    /// Opening a handle is what installs and starts the driver service, so the
    /// first call on a machine is also the one that surfaces a missing or
    /// unloadable `WinDivert64.sys`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the filter is rejected or the
    /// driver cannot be started. `ERROR_ACCESS_DENIED` means the process is
    /// not elevated; `ERROR_INVALID_IMAGE_HASH` means the driver's signature
    /// was refused.
    pub(crate) fn open(
        self: &Arc<Self>,
        filter: &str,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> Result<Handle, ClientError> {
        let filter = CString::new(filter).map_err(|_| {
            ClientError::Platform("WinDivert filter contained an interior NUL".to_owned())
        })?;
        // SAFETY: `filter` is NUL-terminated and outlives the call; WinDivert
        // copies the compiled filter into the driver before returning.
        let handle = unsafe { (self.open)(filter.as_ptr(), layer, priority, flags) };
        if handle == INVALID_HANDLE_VALUE {
            const ERROR_INVALID_PARAMETER: i32 = 87;
            let error = std::io::Error::last_os_error();
            // The most common cause of this code is a filter the driver will
            // not accept, and the compiler can say exactly why.
            if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER) {
                self.check_filter(filter.to_str().unwrap_or_default(), layer)?;
            }
            return Err(open_error(&error));
        }
        Ok(Handle {
            library: Arc::clone(self),
            handle: handle as usize,
        })
    }

    /// Measures the first packet in a concatenated batch.
    ///
    /// A batch carries no framing, so the packets have to be separated by
    /// their own headers. Reading the length field directly looks simpler and
    /// is wrong often enough to matter: an outbound packet built for segment
    /// offload declares a length its buffer does not have, and mis-splitting
    /// one batch corrupts every packet after it. `WinDivert` already knows how
    /// to walk its own batches, so this asks it.
    ///
    /// Returns `None` for a packet it cannot parse, which means the rest of
    /// the batch can no longer be located and must be abandoned.
    pub(crate) fn first_packet_len(&self, bytes: &[u8]) -> Option<usize> {
        let length = u32::try_from(bytes.len()).ok()?;
        let mut next: *const u8 = ptr::null();
        let mut next_len = 0_u32;
        // SAFETY: `bytes` outlives the call and `length` is its true length.
        // Every header output is optional and passed as null; only the pair
        // describing the remainder is read back.
        let ok = unsafe {
            (self.parse_packet)(
                bytes.as_ptr(),
                length,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut next,
                &raw mut next_len,
            )
        };
        if ok == 0 {
            return None;
        }
        let remainder = if next.is_null() { 0 } else { next_len as usize };
        bytes.len().checked_sub(remainder).filter(|len| *len > 0)
    }
}

/// An open `WinDivert` handle.
///
/// Dropping the handle closes it, which is also what lets `WinDivert` stop the
/// driver service once the last handle in the system goes away. A helper that
/// crashes therefore cannot leave the machine diverting packets to nowhere.
pub(crate) struct Handle {
    library: Arc<Library>,
    handle: usize,
}

// SAFETY: WinDivert handles are ordinary kernel handles and are documented as
// safe to use concurrently; the packet threads rely on that.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    /// Receives one packet or event.
    ///
    /// Returns the number of bytes written into `packet`, which is zero for the
    /// event layers such as flow. A shut-down handle reports `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the receive fails for any reason
    /// other than the handle being shut down.
    pub(crate) fn recv(
        &self,
        packet: &mut [u8],
        address: &mut Address,
    ) -> Result<Option<usize>, ClientError> {
        const ERROR_NO_DATA: i32 = 232;
        let capacity = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        let mut received = 0_u32;
        // SAFETY: the buffer and address outlive the call and `capacity` never
        // exceeds the buffer length.
        let ok = unsafe {
            (self.library.recv)(
                self.handle as HANDLE,
                packet.as_mut_ptr(),
                capacity,
                &raw mut received,
                address,
            )
        };
        if ok != 0 {
            return Ok(Some(received as usize));
        }
        let error = std::io::Error::last_os_error();
        // A shutdown drains the queue and then reports no more data. That is
        // an orderly stop, not a failure.
        if error.raw_os_error() == Some(ERROR_NO_DATA) {
            return Ok(None);
        }
        Err(ClientError::Platform(format!(
            "WinDivert receive failed: {error}"
        )))
    }

    /// Injects `packet` back into the network stack.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the injection is rejected.
    pub(crate) fn send(&self, packet: &[u8], address: &Address) -> Result<usize, ClientError> {
        let length = u32::try_from(packet.len())
            .map_err(|_| ClientError::Platform("packet is too large for WinDivert".to_owned()))?;
        let mut sent = 0_u32;
        // SAFETY: the packet and address outlive the call.
        let ok = unsafe {
            (self.library.send)(
                self.handle as HANDLE,
                packet.as_ptr(),
                length,
                &raw mut sent,
                address,
            )
        };
        if ok == 0 {
            return Err(ClientError::Platform(format!(
                "WinDivert injection failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(sent as usize)
    }

    /// Receives every packet the driver has queued, up to what `packets` and
    /// `addresses` hold.
    ///
    /// Returns the bytes written into `packets` and the number of addresses
    /// filled, or `None` once the handle is shut down. The packets are
    /// concatenated with no framing of their own; split them with
    /// [`Library::first_packet_len`].
    ///
    /// This is the whole reason the capture loop keeps up. One `recv` per
    /// packet is one kernel transition per packet, and a split tunnel sees
    /// every packet the machine sends, not only the ones it tunnels. Draining
    /// the queue in one call turns that fixed cost into a per-batch one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the receive fails for any reason
    /// other than the handle being shut down.
    pub(crate) fn recv_batch(
        &self,
        packets: &mut [u8],
        addresses: &mut [Address],
    ) -> Result<Option<(usize, usize)>, ClientError> {
        const ERROR_NO_DATA: i32 = 232;
        let capacity = u32::try_from(packets.len()).unwrap_or(u32::MAX);
        let mut received = 0_u32;
        let mut address_bytes = u32::try_from(std::mem::size_of_val(addresses)).unwrap_or(u32::MAX);
        // SAFETY: both buffers outlive the call and their lengths are passed
        // exactly as measured. A null overlapped pointer asks for a blocking
        // receive, which is what this loop wants.
        let ok = unsafe {
            (self.library.recv_ex)(
                self.handle as HANDLE,
                packets.as_mut_ptr(),
                capacity,
                &raw mut received,
                0,
                addresses.as_mut_ptr(),
                &raw mut address_bytes,
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            let filled = address_bytes as usize / size_of::<Address>();
            // `pAddrLen` is a byte count, which is what the batch is split by.
            // Were it ever a packet count instead, this division would floor
            // to zero and the loop would silently discard every packet the
            // machine sends — an entirely dead network with nothing in the log
            // to say why. Refusing to continue turns that into one sentence.
            if filled == 0 && received != 0 {
                return Err(ClientError::Platform(format!(
                    "WinDivert returned {received} byte(s) of packets against {address_bytes} \
                     byte(s) of addresses, which is not a whole number of addresses; the \
                     WinDivert.dll beside MouseVPN does not match the expected 2.2 ABI"
                )));
            }
            return Ok(Some((received as usize, filled)));
        }
        let error = std::io::Error::last_os_error();
        // A shutdown drains the queue and then reports no more data. That is
        // an orderly stop, not a failure.
        if error.raw_os_error() == Some(ERROR_NO_DATA) {
            return Ok(None);
        }
        Err(ClientError::Platform(format!(
            "WinDivert batch receive failed: {error}"
        )))
    }

    /// Injects a run of concatenated packets, one per entry in `addresses`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the injection is rejected.
    pub(crate) fn send_batch(
        &self,
        packets: &[u8],
        addresses: &[Address],
    ) -> Result<usize, ClientError> {
        if addresses.is_empty() || packets.is_empty() {
            return Ok(0);
        }
        let length = u32::try_from(packets.len()).map_err(|_| {
            ClientError::Platform("packet batch is too large for WinDivert".to_owned())
        })?;
        let address_bytes = u32::try_from(std::mem::size_of_val(addresses)).map_err(|_| {
            ClientError::Platform("address batch is too large for WinDivert".to_owned())
        })?;
        let mut sent = 0_u32;
        // SAFETY: both buffers outlive the call and their lengths are passed
        // exactly as measured; a null overlapped pointer means synchronous.
        let ok = unsafe {
            (self.library.send_ex)(
                self.handle as HANDLE,
                packets.as_ptr(),
                length,
                &raw mut sent,
                0,
                addresses.as_ptr(),
                address_bytes,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(ClientError::Platform(format!(
                "WinDivert batch injection failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(sent as usize)
    }

    /// Enlarges the driver-side queue behind this handle.
    ///
    /// Reported rather than fatal: a driver that refuses a parameter still
    /// captures correctly with its defaults, and losing the tunnel over a
    /// tuning knob would be a worse outcome than the smaller queue.
    pub(crate) fn tune_queues(&self) {
        for (param, value, name) in [
            (PARAM_QUEUE_LENGTH, QUEUE_LENGTH, "length"),
            (PARAM_QUEUE_SIZE, QUEUE_SIZE, "size"),
            (PARAM_QUEUE_TIME, QUEUE_TIME, "time"),
        ] {
            // SAFETY: the handle stays valid for the life of this call.
            let ok = unsafe { (self.library.set_param)(self.handle as HANDLE, param, value) };
            if ok == 0 {
                eprintln!(
                    "MOUSEVPN_DIVERT_WARNING=WinDivert kept its default queue {name}: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    /// Recomputes whichever checksums a rewritten packet invalidated.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when `WinDivert` cannot parse the packet.
    pub(crate) fn calc_checksums(
        &self,
        packet: &mut [u8],
        address: &mut Address,
    ) -> Result<(), ClientError> {
        let length = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        // SAFETY: the packet and address outlive the call; a zero flag word
        // asks for every checksum the packet actually carries.
        let ok = unsafe { (self.library.calc_checksums)(packet.as_mut_ptr(), length, address, 0) };
        if ok == 0 {
            return Err(ClientError::Platform(format!(
                "WinDivert could not recompute checksums: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Measures the first packet of a batch received on this handle.
    ///
    /// See [`Library::first_packet_len`].
    pub(crate) fn first_packet_len(&self, bytes: &[u8]) -> Option<usize> {
        self.library.first_packet_len(bytes)
    }

    /// Unblocks a thread parked in [`Handle::recv`].
    ///
    /// This is the only safe way to stop a receive loop: closing the handle
    /// from another thread while a receive is in flight is a use-after-free.
    pub(crate) fn shutdown(&self) {
        // SAFETY: the handle stays valid until `Drop`, which cannot run while
        // a caller still holds a reference.
        unsafe {
            (self.library.shutdown)(self.handle as HANDLE, SHUTDOWN_BOTH);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was produced by `WinDivertOpen` and is closed
        // exactly once.
        unsafe {
            (self.library.close)(self.handle as HANDLE);
        }
    }
}

/// Resolves one export, failing when the DLL predates the pinned version.
unsafe fn resolve(
    module: windows_sys::Win32::Foundation::HMODULE,
    name: &std::ffi::CStr,
) -> Result<*const (), ClientError> {
    // SAFETY: `name` is NUL-terminated and `module` came from `LoadLibraryW`.
    let symbol = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
    symbol.map(|address| address as *const ()).ok_or_else(|| {
        ClientError::Platform(format!(
            "WinDivert.dll does not export {}; expected the vendored 2.2 build",
            name.to_string_lossy()
        ))
    })
}

/// Locates `WinDivert.dll` beside the running executable.
fn library_path() -> Result<PathBuf, ClientError> {
    let executable = std::env::current_exe().map_err(|error| {
        ClientError::Platform(format!("failed to locate the MouseVPN executable: {error}"))
    })?;
    let directory = executable.parent().ok_or_else(|| {
        ClientError::Platform("the MouseVPN executable has no parent directory".to_owned())
    })?;
    let path = directory.join("WinDivert.dll");
    if !path.is_file() {
        return Err(missing_library(directory));
    }
    // The DLL installs the driver from its own directory, so a present DLL
    // with no .sys beside it fails later, inside WinDivertOpen, with a much
    // less obvious error.
    if !directory.join("WinDivert64.sys").is_file() {
        return Err(ClientError::Platform(format!(
            "WinDivert64.sys is missing from {}; the split tunnel driver cannot start",
            directory.display()
        )));
    }
    Ok(path)
}

fn missing_library(directory: &Path) -> ClientError {
    ClientError::Platform(format!(
        "WinDivert.dll is missing from {}; reinstall MouseVPN to restore it",
        directory.display()
    ))
}

/// Turns the documented `WinDivertOpen` failures into actionable messages.
fn open_error(error: &std::io::Error) -> ClientError {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_INVALID_IMAGE_HASH: i32 = 577;
    const ERROR_DRIVER_BLOCKED: i32 = 1275;
    let message = match error.raw_os_error() {
        Some(ERROR_ACCESS_DENIED) => {
            "MouseVPN must be started as Administrator to open WinDivert".to_owned()
        }
        Some(ERROR_INVALID_IMAGE_HASH) => {
            "Windows refused the WinDivert driver signature; the vendored WinDivert64.sys is \
             damaged or was replaced"
                .to_owned()
        }
        Some(ERROR_DRIVER_BLOCKED) => {
            "Windows blocked the WinDivert driver, usually via the vulnerable driver blocklist \
             or a security policy"
                .to_owned()
        }
        _ => format!("failed to open a WinDivert handle: {error}"),
    };
    ClientError::Platform(message)
}

#[cfg(test)]
mod tests {
    use super::{Address, FlowData, EVENT_FLOW_ESTABLISHED, LAYER_FLOW, LAYER_NETWORK};

    #[test]
    fn address_matches_the_windivert_abi() {
        // WINDIVERT_ADDRESS is a 64-bit timestamp, one packed word, one
        // reserved word and a 64-byte union.
        assert_eq!(size_of::<Address>(), 80);
        assert_eq!(align_of::<Address>(), 8);
        // WINDIVERT_DATA_FLOW has to fit the union it shares.
        assert!(size_of::<FlowData>() <= 64);
    }

    #[test]
    fn decodes_the_packed_layer_and_event_word() {
        let mut address = Address::zeroed();
        // Layer occupies the low byte and Event the next; bit 20 is IPv6.
        address.bitfield = LAYER_FLOW | (EVENT_FLOW_ESTABLISHED << 8) | (1 << 20);
        assert_eq!(address.layer(), LAYER_FLOW);
        assert_eq!(address.event(), EVENT_FLOW_ESTABLISHED);
        assert!(address.ipv6());
        assert!(address.flow().is_some());
    }

    #[test]
    fn reads_the_union_only_for_the_matching_layer() {
        let mut address = Address::zeroed();
        address.bitfield = LAYER_NETWORK;
        assert!(address.flow().is_none());
    }

    #[test]
    fn builds_an_inbound_address_carrying_the_interface() {
        let address = Address::for_inbound(17, 0);
        // Layer network, and the outbound bit clear is what marks it inbound.
        assert_eq!(address.layer(), LAYER_NETWORK);
        assert_eq!(address.bitfield >> 17 & 1, 0);
        assert_eq!(address.payload[..4], 17_u32.to_ne_bytes());
    }
}
