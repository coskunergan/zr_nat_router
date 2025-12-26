// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0
// Coskun ERGAN <coskunergan@gmail.com>

#![allow(unexpected_cfgs)]

use cty::intptr_t;

#[repr(C)]
pub struct SysSNode {
    pub next: *mut SysSNode,
}

#[repr(C)]
pub struct NetBuf {
    node: SysSNode,         // sys_snode_t node;
    pub frags: *mut NetBuf, // struct net_buf *frags;
    r#ref: u8,              // uint8_t ref;
    flags: u8,              // uint8_t flags;
    pool_id: u8,            // uint8_t pool_id;
    user_data_size: u8,     // uint8_t user_data_size;
    pub data: *mut u8,      // uint8_t *data;
    pub len: u16,           // uint16_t len;
    pub size: u16,          // uint16_t size;
    __buf: *mut u8,         // uint8_t *__buf;
}

#[repr(C)]
pub struct KMemSlab {
    _private: [u8; 0],
}

#[repr(C)]
pub struct NetPktCursor {
    buf: *mut NetBuf,
    pos: *mut u8,
}

#[repr(C)]
pub struct NetContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct NetIf {
    _private: [u8; 0],
}

#[repr(C)]
pub struct NetPkt {
    fifo: intptr_t,
    slab: *mut KMemSlab,
    frags_or_buffer: *mut NetBuf,
    cursor: NetPktCursor,
    context: *mut NetContext,
    pub iface: *mut NetIf,
}

impl NetPkt {
    #[inline(always)]
    pub unsafe fn frags(&self) -> *mut NetBuf {
        self.frags_or_buffer
    }

    #[inline(always)]
    pub unsafe fn iface(&self) -> *mut NetIf {
        self.iface
    }

    #[inline(always)]
    pub unsafe fn set_iface(&mut self, iface: *mut NetIf) {
        self.iface = iface;
    }
}

/// IPv4 header structure (matching Zephyr's net_ipv4_hdr)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub vhl: u8,         // Version + IHL
    pub tos: u8,         // Type of service
    pub len: [u8; 2],    // Total length (big-endian)
    pub id: [u8; 2],     // Identification
    pub offset: [u8; 2], // Flags + fragment offset
    pub ttl: u8,         // Time to live
    pub proto: u8,       // Protocol (TCP=6, UDP=17, ICMP=1)
    pub chksum: u16,     // Header checksum
    pub src: [u8; 4],    // Source IP
    pub dst: [u8; 4],    // Destination IP
}

#[cfg(CONFIG_TIMEOUT_64BIT)]
pub type KtickT = i64;

#[cfg(not(CONFIG_TIMEOUT_64BIT))]
pub type KtickT = u32;

extern "C" {
    /// packet send interface
    pub fn net_try_send_data(pkt: *mut NetPkt, timeout: KtickT) -> i32;
}
