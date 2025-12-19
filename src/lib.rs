// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0
// Coskun ERGAN <coskunergan@gmail.com>

#![no_std]

extern crate alloc;
use alloc::format;

use embassy_time::{Duration, Timer};

#[cfg(feature = "executor-thread")]
use embassy_executor::Executor;

#[cfg(feature = "executor-zephyr")]
use zephyr::embassy::Executor;

use embassy_executor::Spawner;
use static_cell::StaticCell;

use zephyr::device::gpio::GpioPin;
use pin::{GlobalPin, Pin};

use crate::wifi::Wifi;

mod ffi;
mod nat;
mod packet;

mod pin;
mod usage;
mod wifi;

static EXECUTOR_MAIN: StaticCell<Executor> = StaticCell::new();
static RED_LED_PIN: GlobalPin = GlobalPin::new();

const VERSION_MAJOR: &str = env!("VERSION_MAJOR");
const VERSION_MINOR: &str = env!("VERSION_MINOR");
const PATCHLEVEL: &str = env!("PATCHLEVEL");
const EXTRAVERSION: &str = env!("EXTRAVERSION");

#[embassy_executor::task]
async fn led_task(spawner: Spawner) {
    let red_led_pin = RED_LED_PIN.get();
    loop {
        log::info!(
            "Loop! Version: {}.{}.{} ({})",
            VERSION_MAJOR,
            VERSION_MINOR,
            PATCHLEVEL,
            EXTRAVERSION
        );
        red_led_pin.toggle();
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[no_mangle]
extern "C" fn rust_main() {
    let _ = usage::set_logger();

    log::info!("Restart!!!\r\n");

    RED_LED_PIN.init(Pin::new(
        zephyr::devicetree::labels::red_led::get_instance().expect("Red Led DeviceTree not found!"),
    ));

    Wifi::wifi_connect();

    let executor = EXECUTOR_MAIN.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(led_task(spawner)).unwrap();
    })
}
