# ZR NAT Router

ZR NAT Router is a real-time capable Network Address Translation (NAT) router designed for constrained embedded systems. The project is implemented in **Rust** and runs on **Zephyr RTOS**, targeting **ESP32 RISC-V** based platforms.

The primary goal of this project is to provide a lightweight, deterministic, and maintainable NAT solution suitable for embedded and edge networking scenarios such as IoT gateways and constrained routing devices.

---

## Overview

This project integrates a Rust-based stateful NAT implementation with Zephyr’s networking subsystem. It is designed to operate within the resource constraints of ESP32-class devices while maintaining predictable runtime behavior and low latency.

ZR NAT Router focuses on correctness, simplicity, and real-time suitability rather than high-throughput routing typically associated with general-purpose network hardware.

---

## Key Characteristics

- Implementation language: Rust
- Operating system: Zephyr RTOS
- Target architecture: ESP32 RISC-V (32-bit)
- Network functionality: IPv4 NAT (stateful)
- Intended use cases: Embedded NAT, IoT gateways, edge networking

---

## Wi-Fi Throughput Comparison

The following table is intended for experimentally measured values;

| Board | Arch | Optimization | CPU Frequency | Throughput | Power |
| ----- | ----- | ----- | ------------ | ------------- | ---------- |
| `ESP32C3 WiFi-4` | `RISC-V` | `0g` | `160MHz` | `3.8 MBits/s` | `1.05 W` |
| `ESP32C6 WiFi-6` | `RISC-V` | `0g` | `160MHz` | `7.5 MBits/s` | `1.25 W` |


### Prerequisites

- Zephyr SDK
- Rust stable toolchain
- ESP32 RISC-V toolchain
- West build system

### Build for ESP32-C6

```sh
west build -b esp32c6_devkitc/esp32c6/hpcore
