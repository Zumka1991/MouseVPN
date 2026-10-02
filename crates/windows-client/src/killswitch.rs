#![doc = "Fail-closed WFP kill switch for the Windows full tunnel."]

use std::{net::Ipv4Addr, ptr};

use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::{
            Ndis::NET_LUID_LH,
            WindowsFilteringPlatform::{
                FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmProviderAdd0,
                FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
                FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_FLAGS,
                FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT,
                FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0,
                FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK,
                FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
                FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ANY_SET, FWP_UINT16,
                FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
                FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
            },
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

use crate::{
    app_bypass::{check_wfp, display_data, wide},
    ClientError,
};

const PROVIDER_KEY: GUID = GUID::from_u128(0x9c8a_1f2b_6d43_4e57_bd10_2f7a_5c93_e604);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x4b7e_05d9_3a16_42c8_9f0d_61c8_b2a7_de35);

/// Sublayer weight.
///
/// This has to sit *below* the application bypass sublayer (`0xfffe`). WFP
/// walks sublayers from the heaviest down, and the bypass permits carry
/// `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, which strips the right to block from
/// every sublayer evaluated after them. Ordering the kill switch underneath is
/// what lets a split-tunnel exclusion keep reaching the internet directly while
/// everything else stays fenced in.
const SUBLAYER_WEIGHT: u16 = 0xfffd;

/// Weight of the catch-all blocks. Nothing sorts below them, so they only
/// decide a connection no permit claimed.
const BLOCK_WEIGHT: u64 = 0;
/// Weight of every exception. Filters are evaluated highest first inside a
/// sublayer, so these all get a look before the catch-all block.
const PERMIT_WEIGHT: u64 = 10;

const IPPROTO_UDP: u8 = 17;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// A dynamic WFP session holding the full-tunnel kill switch.
///
/// Dynamic sessions are the reason this replaces the Windows Firewall rules
/// rather than joining them: the filters exist only while this handle is open,
/// so a helper that crashes or is killed cannot leave the machine behind a
/// policy nothing will clean up. It also means the whole kill switch installs
/// in one transaction instead of two `New-NetFirewallRule` calls per adapter.
pub(crate) struct KillSwitch {
    // Stored as a `usize` so the guard stays `Send`, matching the application
    // bypass engine.
    engine: usize,
}

impl KillSwitch {
    /// Blocks every outbound connection that neither uses the tunnel nor talks
    /// to the tunnel endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the WFP engine cannot be opened or a filter is
    /// rejected. The transaction is atomic, so a failure leaves no filters
    /// behind and traffic keeps flowing as before.
    pub(crate) fn install(server_ip: Ipv4Addr, tunnel: NET_LUID_LH) -> Result<Self, ClientError> {
        let mut session_name = wide("MouseVPN kill switch");
        let session = FWPM_SESSION0 {
            displayData: display_data(&mut session_name),
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = ptr::null_mut();
        check_wfp(
            unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &raw const session,
                    &raw mut engine,
                )
            },
            "open the kill switch WFP engine",
        )?;
        let tunnel = unsafe { tunnel.Value };
        if let Err(error) = configure_engine(engine, server_ip, tunnel) {
            unsafe {
                FwpmEngineClose0(engine);
            }
            return Err(error);
        }
        Ok(Self {
            engine: engine as usize,
        })
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.engine != 0 {
            unsafe {
                FwpmEngineClose0(self.engine as HANDLE);
            }
            self.engine = 0;
        }
    }
}

fn configure_engine(engine: HANDLE, server_ip: Ipv4Addr, tunnel: u64) -> Result<(), ClientError> {
    check_wfp(
        unsafe { FwpmTransactionBegin0(engine, 0) },
        "begin the kill switch WFP transaction",
    )?;
    match configure_transaction(engine, server_ip, tunnel) {
        Ok(()) => check_wfp(
            unsafe { FwpmTransactionCommit0(engine) },
            "commit the kill switch WFP transaction",
        ),
        Err(error) => {
            unsafe {
                FwpmTransactionAbort0(engine);
            }
            Err(error)
        }
    }
}

fn configure_transaction(
    engine: HANDLE,
    server_ip: Ipv4Addr,
    tunnel: u64,
) -> Result<(), ClientError> {
    let mut provider_name = wide("MouseVPN kill switch");
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: display_data(&mut provider_name),
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmProviderAdd0(engine, &raw const provider, ptr::null_mut()) },
        "add the MouseVPN kill switch provider",
    )?;

    let mut sublayer_name = wide("MouseVPN kill switch policy");
    let mut provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: display_data(&mut sublayer_name),
        providerKey: ptr::from_mut(&mut provider_key),
        weight: SUBLAYER_WEIGHT,
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmSubLayerAdd0(engine, &raw const sublayer, ptr::null_mut()) },
        "add the MouseVPN kill switch sublayer",
    )?;
    add_ipv4_filters(engine, server_ip, tunnel)?;
    add_ipv6_filters(engine)
}

/// Denies IPv4 unless it leaves through the tunnel, is the tunnel's own
/// transport, is loopback, or is the DHCP exchange that keeps the physical link
/// addressed.
fn add_ipv4_filters(engine: HANDLE, server_ip: Ipv4Addr, tunnel: u64) -> Result<(), ClientError> {
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWP_ACTION_BLOCK,
        BLOCK_WEIGHT,
        &mut [],
        "MouseVPN kill switch IPv4 block",
    )?;
    let mut tunnel_luid = tunnel;
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT,
        &mut [interface_condition(&mut tunnel_luid)],
        "MouseVPN kill switch IPv4 tunnel permit",
    )?;
    let mut server = FWP_V4_ADDR_AND_MASK {
        addr: u32::from(server_ip),
        mask: u32::MAX,
    };
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT,
        &mut [remote_ipv4_condition(&mut server)],
        "MouseVPN kill switch IPv4 endpoint permit",
    )?;
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT,
        &mut [loopback_condition()],
        "MouseVPN kill switch IPv4 loopback permit",
    )?;
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT,
        &mut [
            u8_condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
            u16_condition(FWPM_CONDITION_IP_LOCAL_PORT, DHCP_CLIENT_PORT),
            u16_condition(FWPM_CONDITION_IP_REMOTE_PORT, DHCP_SERVER_PORT),
        ],
        "MouseVPN kill switch IPv4 DHCP permit",
    )
}

/// Denies IPv6 outright. The tunnel is IPv4 only, so nothing but loopback and
/// on-link neighbours has anywhere legitimate to go.
fn add_ipv6_filters(engine: HANDLE) -> Result<(), ClientError> {
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWP_ACTION_BLOCK,
        BLOCK_WEIGHT,
        &mut [],
        "MouseVPN kill switch IPv6 block",
    )?;
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT,
        &mut [loopback_condition()],
        "MouseVPN kill switch IPv6 loopback permit",
    )?;
    let mut link_local = FWP_V6_ADDR_AND_MASK {
        addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefixLength: 10,
    };
    add_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWP_ACTION_PERMIT,
        PERMIT_WEIGHT,
        &mut [remote_ipv6_condition(&mut link_local)],
        "MouseVPN kill switch IPv6 link-local permit",
    )
}

fn add_filter(
    engine: HANDLE,
    layer: GUID,
    action: u32,
    weight: u64,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    name: &str,
) -> Result<(), ClientError> {
    let mut name_buffer = wide(name);
    let mut provider_key = PROVIDER_KEY;
    let mut weight = weight;
    let filter = FWPM_FILTER0 {
        displayData: display_data(&mut name_buffer),
        providerKey: ptr::from_mut(&mut provider_key),
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: ptr::from_mut(&mut weight),
            },
        },
        numFilterConditions: u32::try_from(conditions.len()).unwrap_or(0),
        filterCondition: if conditions.is_empty() {
            ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        },
        action: FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        },
        ..Default::default()
    };
    check_wfp(
        unsafe { FwpmFilterAdd0(engine, &raw const filter, ptr::null_mut(), ptr::null_mut()) },
        &format!("add the '{name}' filter"),
    )
}

fn interface_condition(luid: &mut u64) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint64: ptr::from_mut(luid),
            },
        },
    }
}

fn remote_ipv4_condition(address: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: ptr::from_mut(address),
            },
        },
    }
}

fn remote_ipv6_condition(address: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v6AddrMask: ptr::from_mut(address),
            },
        },
    }
}

fn loopback_condition() -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ANY_SET,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        },
    }
}

fn u8_condition(field: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: value },
        },
    }
}

fn u16_condition(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
        },
    }
}
