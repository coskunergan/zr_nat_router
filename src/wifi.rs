// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0
// Coskun ERGAN <coskunergan@gmail.com>

use core::str;
use heapless::String;
use zephyr::kconfig::{CONFIG_WIFI_SAMPLE_PSK as PSK_RAW, CONFIG_WIFI_SAMPLE_SSID as SSID_RAW};

extern "C" {
    fn wifi_connect();
}

fn get_default_ssid() -> String<32> {
    let mut s = String::<32>::new();
    let cleaned = SSID_RAW
        .as_bytes()
        .splitn(2, |&b| b == 0)
        .next()
        .unwrap_or(&[]);
    if let Ok(text) = str::from_utf8(cleaned) {
        let _ = s.push_str(text);
    }
    if s.is_empty() {
        let _ = s.push_str("MyWiFi");
    }
    s
}

fn get_default_psk() -> String<64> {
    let mut s = String::<64>::new();
    let cleaned = PSK_RAW
        .as_bytes()
        .splitn(2, |&b| b == 0)
        .next()
        .unwrap_or(&[]);
    if let Ok(text) = str::from_utf8(cleaned) {
        let _ = s.push_str(text);
    }
    if s.is_empty() {
        let _ = s.push_str("12345678");
    }
    s
}

pub struct Wifi {
    _private: (),
}

impl Wifi {
    pub fn wifi_connect() {
        let (ssid, psk) = (get_default_ssid(), get_default_psk());
        unsafe {
            set_wifi_credentials(ssid.as_bytes(), psk.as_bytes());
        }
        unsafe { wifi_connect() };
    }
}

static mut CURRENT_SSID: [u8; 33] = [0; 33];
static mut CURRENT_PSK: [u8; 65] = [0; 65];

static mut CURRENT_SSID_LEN: u8 = 0;
static mut CURRENT_PSK_LEN: u8 = 0;

static mut CURRENT_SSID_PTR: *mut u8 = core::ptr::null_mut();
static mut CURRENT_PSK_PTR: *mut u8 = core::ptr::null_mut();

unsafe fn set_wifi_credentials(ssid: &[u8], psk: &[u8]) {
    CURRENT_SSID = [0; 33];
    CURRENT_PSK = [0; 65];

    let ssid_len = ssid.len().min(32);
    CURRENT_SSID[..ssid_len].copy_from_slice(&ssid[..ssid_len]);
    CURRENT_SSID_LEN = ssid_len as u8;

    let psk_len = psk.len().min(64);
    CURRENT_PSK[..psk_len].copy_from_slice(&psk[..psk_len]);
    CURRENT_PSK_LEN = psk_len as u8;

    CURRENT_SSID_PTR = core::ptr::addr_of_mut!(CURRENT_SSID) as *mut u8;
    CURRENT_PSK_PTR = core::ptr::addr_of_mut!(CURRENT_PSK) as *mut u8;
}

#[no_mangle]
pub unsafe extern "C" fn get_current_ssid() -> *const u8 {
    CURRENT_SSID_PTR as *const u8
}

#[no_mangle]
pub unsafe extern "C" fn get_current_ssid_len() -> u8 {
    CURRENT_SSID_LEN
}

#[no_mangle]
pub unsafe extern "C" fn get_current_psk() -> *const u8 {
    CURRENT_PSK_PTR as *const u8
}

#[no_mangle]
pub unsafe extern "C" fn get_current_psk_len() -> u8 {
    CURRENT_PSK_LEN
}
