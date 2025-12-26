// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0
// Coskun ERGAN <coskunergan@gmail.com>

use crate::ffi::NetIf;
use crate::ffi::*;
use crate::nat::checksum::{ip_checksum, update_checksum};
use core::ptr;

#[derive(Clone, Copy)]
pub struct PacketContext {
    pub ip_hdr: Ipv4Hdr,
    pub src_port: u16,
    pub dst_port: u16,
    pub needs_update: bool,
    pub iface: *mut NetIf,
    pub orig_iface: *mut NetIf,
}

impl PacketContext {
    pub fn from_pkt(pkt: *mut NetPkt) -> Option<Self> {
        if pkt.is_null() {
            return None;
        }

        unsafe {
            let iface = (*pkt).iface();
            let frags = (*pkt).frags();

            if frags.is_null() {
                return None;
            }

            let buf_ptr = (*frags).data;

            if buf_ptr.is_null() {
                return None;
            }

            let min_slice = core::slice::from_raw_parts(buf_ptr, 20);
            if min_slice.len() < 20 {
                return None;
            }

            let vhl = min_slice[0];
            if vhl >> 4 != 4 {
                return None;
            }

            let ihl = ((vhl & 0x0F) as usize) * 4;
            if ihl < 20 || ihl > 60 {
                return None;
            }

            let full_hdr = core::slice::from_raw_parts(buf_ptr, ihl);
            if full_hdr.len() < ihl {
                return None;
            }

            let ip_hdr = Ipv4Hdr {
                vhl,
                tos: full_hdr[1],
                len: [full_hdr[2], full_hdr[3]],
                id: [full_hdr[4], full_hdr[5]],
                offset: [full_hdr[6], full_hdr[7]],
                ttl: full_hdr[8],
                proto: full_hdr[9],
                chksum: u16::from_be_bytes([full_hdr[10], full_hdr[11]]),
                src: [full_hdr[12], full_hdr[13], full_hdr[14], full_hdr[15]],
                dst: [full_hdr[16], full_hdr[17], full_hdr[18], full_hdr[19]],
            };

            let (src_port, dst_port) = match ip_hdr.proto {
                6 | 17 => {
                    let l4 = core::slice::from_raw_parts(buf_ptr.add(ihl), 4);
                    if l4.len() >= 4 {
                        (
                            u16::from_be_bytes([l4[0], l4[1]]),
                            u16::from_be_bytes([l4[2], l4[3]]),
                        )
                    } else {
                        (0, 0)
                    }
                }
                1 => {
                    let l4 = core::slice::from_raw_parts(buf_ptr.add(ihl), 8);
                    if l4.len() >= 8 {
                        (u16::from_be_bytes([l4[4], l4[5]]), 0)
                    } else {
                        (0, 0)
                    }
                }
                _ => (0, 0),
            };

            Some(Self {
                ip_hdr,
                src_port,
                dst_port,
                needs_update: false,
                iface,
                orig_iface: iface,
            })
        }
    }

    pub fn apply_to_pkt(&mut self, pkt: *mut NetPkt) {
        if pkt.is_null() || !self.needs_update {
            return;
        }

        unsafe {
            if !self.iface.is_null() && self.iface != self.orig_iface {
                (*pkt).set_iface(self.iface);
            }

            let frags = (*pkt).frags();

            if frags.is_null() {
                return;
            }

            let buf_ptr = (*frags).data;

            if buf_ptr.is_null() {
                return;
            }

            let ihl = ((self.ip_hdr.vhl & 0x0F) as usize) * 4;

            let old_src_ip = *(buf_ptr.add(12) as *const [u8; 4]);
            let old_dst_ip = *(buf_ptr.add(16) as *const [u8; 4]);

            ptr::copy_nonoverlapping(self.ip_hdr.src.as_ptr(), buf_ptr.add(12), 4);
            ptr::copy_nonoverlapping(self.ip_hdr.dst.as_ptr(), buf_ptr.add(16), 4);

            // === IP Checksum  ===
            let ip_changed = old_src_ip != self.ip_hdr.src || old_dst_ip != self.ip_hdr.dst;

            if ip_changed {
                let ip_hdr_full = core::slice::from_raw_parts_mut(buf_ptr, ihl);
                ip_hdr_full[10] = 0;
                ip_hdr_full[11] = 0;
                let csum = ip_checksum(&ip_hdr_full[..ihl]);
                ip_hdr_full[10] = (csum >> 8) as u8;
                ip_hdr_full[11] = csum as u8;
            }

            // === Transport Layer (TCP/UDP) ===
            let l4_ptr = buf_ptr.add(ihl);

            match self.ip_hdr.proto {
                6 => {
                    // TCP
                    self.update_tcp_checksum(l4_ptr, old_src_ip, old_dst_ip, ip_changed);
                }
                17 => {
                    // UDP
                    self.update_udp_checksum(l4_ptr, old_src_ip, old_dst_ip, ip_changed);
                }
                _ => {}
            }
        }
    }

    #[inline(always)]
    unsafe fn update_tcp_checksum(
        &self,
        tcp_ptr: *mut u8,
        old_src_ip: [u8; 4],
        old_dst_ip: [u8; 4],
        ip_changed: bool,
    ) {
        let tcp_hdr = core::slice::from_raw_parts_mut(tcp_ptr, 20);
        if tcp_hdr.len() < 20 {
            return;
        }

        let old_src_port = u16::from_be_bytes([tcp_hdr[0], tcp_hdr[1]]);
        let old_dst_port = u16::from_be_bytes([tcp_hdr[2], tcp_hdr[3]]);
        let mut csum = u16::from_be_bytes([tcp_hdr[16], tcp_hdr[17]]);

        // Port güncellemeleri
        tcp_hdr[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        tcp_hdr[2..4].copy_from_slice(&self.dst_port.to_be_bytes());

        // Port değişiklikleri için checksum güncelle
        if old_src_port != self.src_port {
            csum = update_checksum(csum, old_src_port, self.src_port);
        }
        if old_dst_port != self.dst_port {
            csum = update_checksum(csum, old_dst_port, self.dst_port);
        }

        // IP değişiklikleri için checksum güncelle
        if ip_changed {
            csum = self.update_checksum_for_ip(csum, old_src_ip, old_dst_ip);
        }

        tcp_hdr[16..18].copy_from_slice(&csum.to_be_bytes());
    }

    #[inline(always)]
    unsafe fn update_udp_checksum(
        &self,
        udp_ptr: *mut u8,
        old_src_ip: [u8; 4],
        old_dst_ip: [u8; 4],
        ip_changed: bool,
    ) {
        let udp_hdr = core::slice::from_raw_parts_mut(udp_ptr, 8);
        if udp_hdr.len() < 8 {
            return;
        }

        let old_src_port = u16::from_be_bytes([udp_hdr[0], udp_hdr[1]]);
        let old_dst_port = u16::from_be_bytes([udp_hdr[2], udp_hdr[3]]);
        let mut csum = u16::from_be_bytes([udp_hdr[6], udp_hdr[7]]);

        // Port güncellemeleri
        udp_hdr[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        udp_hdr[2..4].copy_from_slice(&self.dst_port.to_be_bytes());

        // UDP checksum 0 ise güncelleme yapma (opsiyonel checksum)
        if csum != 0 {
            // Port değişiklikleri için checksum güncelle
            if old_src_port != self.src_port {
                csum = update_checksum(csum, old_src_port, self.src_port);
            }
            if old_dst_port != self.dst_port {
                csum = update_checksum(csum, old_dst_port, self.dst_port);
            }

            // IP değişiklikleri için checksum güncelle
            if ip_changed {
                csum = self.update_checksum_for_ip(csum, old_src_ip, old_dst_ip);
            }

            udp_hdr[6..8].copy_from_slice(&csum.to_be_bytes());
        }
    }

    #[inline(always)]
    fn update_checksum_for_ip(
        &self,
        mut csum: u16,
        old_src_ip: [u8; 4],
        old_dst_ip: [u8; 4],
    ) -> u16 {
        // Kaynak IP değiştiyse
        if old_src_ip != self.ip_hdr.src {
            let old_src_hi = u16::from_be_bytes([old_src_ip[0], old_src_ip[1]]);
            let old_src_lo = u16::from_be_bytes([old_src_ip[2], old_src_ip[3]]);
            let new_src_hi = u16::from_be_bytes([self.ip_hdr.src[0], self.ip_hdr.src[1]]);
            let new_src_lo = u16::from_be_bytes([self.ip_hdr.src[2], self.ip_hdr.src[3]]);

            if old_src_hi != new_src_hi {
                csum = update_checksum(csum, old_src_hi, new_src_hi);
            }
            if old_src_lo != new_src_lo {
                csum = update_checksum(csum, old_src_lo, new_src_lo);
            }
        }

        // Hedef IP değiştiyse
        if old_dst_ip != self.ip_hdr.dst {
            let old_dst_hi = u16::from_be_bytes([old_dst_ip[0], old_dst_ip[1]]);
            let old_dst_lo = u16::from_be_bytes([old_dst_ip[2], old_dst_ip[3]]);
            let new_dst_hi = u16::from_be_bytes([self.ip_hdr.dst[0], self.ip_hdr.dst[1]]);
            let new_dst_lo = u16::from_be_bytes([self.ip_hdr.dst[2], self.ip_hdr.dst[3]]);

            if old_dst_hi != new_dst_hi {
                csum = update_checksum(csum, old_dst_hi, new_dst_hi);
            }
            if old_dst_lo != new_dst_lo {
                csum = update_checksum(csum, old_dst_lo, new_dst_lo);
            }
        }

        csum
    }
}
