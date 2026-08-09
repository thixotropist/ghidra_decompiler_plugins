---
title: RISC-V drone vendors
description: Which vendors are likely to use risc-v processors in drones?
weight: 20
---

## User Request
which vendors are likely to use risc-v processors in drones?

---

## Response

The adoption of **RISC-V processors in drones and Unmanned Aerial Vehicles (UAVs)** is accelerating rapidly. The shift away from traditional ARM-based (e.g., STM32) and x86 architectures is driven by three main factors: **supply chain sovereignty (NDAA compliance)**, **extreme power efficiency for lightweight/nano drones**, and **hardware-level security for autonomous flight control**.

Drone vendors and chipmakers likely to use—or already using—RISC-V fall into four major categories:

---

### 1. Sovereign Defense & High-Security Drone Builders
Defense drone manufacturers facing strict national security mandates (such as the U.S. National Defense Authorization Act / NDAA, Blue UAS, and European defense sovereignty initiatives) are primary candidates for RISC-V. Open architecture allows them to verify silicon for backdoors and avoid foreign IP dependencies.

* **Technology Innovation Institute (TII / SSRC - UAE):** A pioneer in secure drone hardware. TII developed the **Shaheen** and **Al Saqr** RISC-V SoCs specifically to run open-source autopilot stacks (like PX4) in a zero-trust, hardware-isolated environment.
* **U.S. Defense Drone OEMs (Anduril, Skydio, Red Cat / Teal, Shield AI, Quantum-Systems):** Under pressure from DoD programs (such as *Drone Dominance* and *Replicator*), these vendors are seeking trusted, NDAA-compliant domestic silicon. RISC-V allows custom security enclaves and custom edge-AI extensions for GPS-denied navigation.
* **Sovereign Defense Contractors in India & Europe:** Organizations leveraging indigenous RISC-V designs (e.g., India's **Shakti** processor program from IIT Madras) to build tamper-proof military UAV autopilots and communications payload controllers.

---

### 2. Micro and Nano-Drone Manufacturers
For tiny drones (micro-UAVs under 100 grams), battery life and thermal constraints are major bottlenecks. RISC-V's modular nature allows ultra-low-power vector accelerators ideal for onboard computer vision and AI.

* **Bitcraze (Crazyflie):** Maker of small open-source research drones. Bitcraze uses RISC-V processor boards (such as the GreenWaves GAP8/GAP9 AI-deck) for real-time onboard neural network inference (obstacle avoidance, human tracking, and SLAM).
* **Academic & Commercial Nano-Drone Developers:** Research groups and commercial spin-offs utilizing the **PULP (Parallel Ultra-Low-Power)** open-source RISC-V architecture developed by ETH Zurich and the University of Bologna for nano-scale autonomous flight.

---

### 3. Open-Source Ecosystem & Flight Controller Manufacturers
Hardware vendors that build commercial flight controller boards (traditionally based on ARM STM32 microcontrollers) for **PX4** and **ArduPilot** ecosystems are actively porting to RISC-V.

* **Pixhawk / Holybro / ModalAI Hardware Ecosystem:** As open-source software projects (PX4 and ArduPilot) mature their RISC-V support, third-party board vendors are evaluating RISC-V MCUs to combat chip shortages, lower licensing costs, and gain higher performance per watt.
* **Electronic Speed Controller (ESC) Makers:** Manufacturers of motor drivers and ESCs running open-source firmware (such as **AM32**) are turning to low-cost RISC-V microcontrollers for high-frequency motor actuation and PWM signal control.

---

### 4. Silicon & IP Vendors Supplying Drone Manufacturers
Behind the drone OEMs are key chipmakers and IP providers producing RISC-V solutions designed specifically for UAV flight control, edge vision, and telemetry:

| Vendor Category | Company | Application in Drones |
| :--- | :--- | :--- |
| **Edge AI & Vision** | **GreenWaves Technologies** | GAP8 & GAP9 multi-core RISC-V processors for ultra-low-power vision and obstacle avoidance. |
| **High-Reliability & Defense** | **Microchip Technology** | **PolarFire SoC FPGA** (hardened RISC-V cores) used for secure, high-reliability mission computing and sensor fusion. |
| **Telemetry & Peripherals** | **Espressif Systems** | **ESP32-C series** (RISC-V based) widely used for drone Wi-Fi/Bluetooth telemetry, secondary payload control, and ESP-Drone development. |
| **IoT & Motor Control** | **Bouffalo Lab / WCH / GigaDevice** | Low-cost RISC-V MCUs integrated into secondary drone control systems, companion sensors, and ESC motor drivers. |
| **Custom IP Licensing** | **SiFive, Andes Tech, Codasip** | Commercial RISC-V processor IP (including vector extensions) licensed by custom UAV chip designers for real-time sensor fusion and flight control. |

---

### Key Reasons Why Drone Vendors Are Moving to RISC-V
1. **Hardware Security & Hypervisor Isolation:** RISC-V hypervisor extensions allow safe separation of critical flight-control code (autopilot) from un-trusted mission payloads (e.g., video streaming or third-party apps) on a single chip.
2. **Domain-Specific Customization:** Drone manufacturers can add custom instruction set extensions (e.g., fast matrix math for camera tracking or specialized PWM handling for motor ESCs).
3. **Supply Chain Resilience:** Eliminates vendor lock-in and foreign export-control vulnerabilities associated with proprietary ISA licenses.