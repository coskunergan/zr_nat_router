// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0
// Coskun ERGAN <coskunergan@gmail.com>

pub mod checksum;
pub mod entry;
pub mod table;

pub use table::NatTable;

use crate::ffi::*;
use crate::packet::PacketContext;

const NAT_TIMEOUT: KtickT = zephyr::kconfig::CONFIG_NET_IPV4_NAT_TIMEOUT as KtickT;

static mut NAT_TABLE: Option<NatTable> = None;

#[no_mangle]
fn nat_outbound(pkt: *mut NetPkt) -> i32 {
    if pkt.is_null() {
        log::error!("[NAT] outbound: pkt is null");
        return -1;
    }

    let table = match unsafe { core::ptr::addr_of_mut!(NAT_TABLE).as_mut().unwrap() } {
        Some(t) => t,
        None => {
            log::error!("[NAT] outbound: NAT table not initialized");
            return -1;
        }
    };

    // Parse packet
    let mut ctx = match PacketContext::from_pkt(pkt) {
        Some(c) => c,
        None => {
            log::error!("[NAT] outbound: failed to parse packet");
            return -1;
        }
    };

    // Perform NAT translation
    match table.translate_outbound(&mut ctx) {
        Ok(_) => {
            // *** CRITICAL: Only apply if needs_update is true ***
            if ctx.needs_update {
                log::info!("[NAT] outbound: Applying changes to packet");
                ctx.apply_to_pkt(pkt);
                return 1;
            } else {
                log::info!("[NAT] outbound: No changes needed, packet unchanged");
            }
            0
        }
        Err(_) => {
            log::error!("[NAT] outbound: translation failed");
            -1
        }
    }
}

/// Process inbound packet (WAN -> LAN)
#[no_mangle]
fn nat_inbound(pkt: *mut NetPkt) -> i32 {
    if pkt.is_null() {
        log::error!("[NAT] inbound: pkt is null");
        return -1;
    }

    let table = match unsafe { core::ptr::addr_of_mut!(NAT_TABLE).as_mut().unwrap() } {
        Some(t) => t,
        None => {
            log::error!("[NAT] inbound: NAT table not initialized");
            return -1;
        }
    };

    // Parse packet
    let mut ctx = match PacketContext::from_pkt(pkt) {
        Some(c) => c,
        None => {
            log::error!("[NAT] inbound: failed to parse packet");
            return -1;
        }
    };

    // // Perform NAT translation
    match table.translate_inbound(&mut ctx) {
        Ok(_) => {
            // *** CRITICAL: Only apply if needs_update is true ***
            if ctx.needs_update {
                log::info!("[NAT] inbound: Applying changes to packet");
                ctx.apply_to_pkt(pkt);
                return 1;
            } else {
                log::info!("[NAT] inbound: No changes needed, packet unchanged");
            }
            0
        }
        Err(_) => {
            //This is OK for inbound - no matching NAT entry
            log::info!("[NAT] inbound: no matching NAT entry (OK for new connections)");
            0 // ← Return 0, not -1!
        }
    }
}

/// TODO: put in to the ipv4.c line: 350
/* NAT HOOK
#if defined(CONFIG_NET_IPV4_NAT)
    extern int nat_hook(struct net_pkt *pkt);
    int nat_ret = nat_hook(pkt);
    if(nat_ret < 0)
    {
        goto drop;
    }
    else if(nat_ret == 1)
    {
        return NET_OK;
    }
#endif
NAT HOOK */

#[no_mangle]
pub unsafe extern "C" fn nat_hook(pkt: *mut NetPkt) -> i32 {
    if pkt.is_null() {
        log::error!("[NAT] hook: pkt is null");
        return -1;
    }

    // First try inbound translation (WAN -> LAN)
    let inbound_result = nat_inbound(pkt);

    match inbound_result {
        1 => {
            // Packet was modified by inbound NAT, send it
            log::info!("[NAT] hook: inbound translation applied, sending packet");
            net_try_send_data(pkt, NAT_TIMEOUT);
            return 1;
        }
        -1 => {
            // Error in inbound processing
            log::error!("[NAT] hook: inbound processing failed");
            return -1;
        }
        0 => {
            // No inbound match, try outbound translation (LAN -> WAN)
            let outbound_result = nat_outbound(pkt);

            match outbound_result {
                1 => {
                    // Packet was modified by outbound NAT, send it
                    log::info!("[NAT] hook: outbound translation applied, sending packet");
                    net_try_send_data(pkt, NAT_TIMEOUT);
                    return 1;
                }
                0 => {
                    // No translation needed, packet can continue normally
                    log::debug!("[NAT] hook: no translation needed");
                    return 0;
                }
                -1 => {
                    // Error in outbound processing
                    log::error!("[NAT] hook: outbound processing failed");
                    return -1;
                }
                _ => {
                    log::error!("[NAT] hook: unexpected outbound result");
                    return -1;
                }
            }
        }
        _ => {
            log::error!("[NAT] hook: unexpected inbound result");
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn nat_configure(
    internal_net: *const u8,
    internal_mask: *const u8,
    external_ip: *const u8,
    internal_iface: *mut NetIf,
    external_iface: *mut NetIf,
) -> i32 {
    unsafe {
        let nat_table = core::ptr::addr_of_mut!(NAT_TABLE).as_mut().unwrap();

        if nat_table.is_none() {
            NAT_TABLE = Some(NatTable::new());
        }

        let table = match nat_table {
            Some(t) => t,
            None => return -1,
        };

        if internal_net.is_null() || internal_mask.is_null() || external_ip.is_null() {
            return -1;
        }

        let mut config = table::NatConfig::default();
        core::ptr::copy_nonoverlapping(internal_net, config.internal_network.as_mut_ptr(), 4);
        core::ptr::copy_nonoverlapping(internal_mask, config.internal_netmask.as_mut_ptr(), 4);
        core::ptr::copy_nonoverlapping(external_ip, config.external_ip.as_mut_ptr(), 4);

        config.internal_iface = internal_iface;
        config.external_iface = external_iface;

        log::info!(
            "[NAT CFG] Internal: {:p}, External: {:p}",
            internal_iface,
            external_iface
        );

        table.set_config(config);
    }
    0
}
