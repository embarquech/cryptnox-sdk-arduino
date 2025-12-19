<p align="center">
  <img src="https://github.com/user-attachments/assets/6ce54a27-8fb6-48e6-9d1f-da144f43425a"/>
</p>

<h3 align="center">cryptnox-sdk-arduino</h3>
<p align="center">Arduino library for managing Cryptnox smart card wallets</p>

<br/>
<br/>

[![License: GPLv3](https://img.shields.io/badge/License-LGPLv3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

`cryptnox-sdk-arduino` is a library that enables the use of **Cryptnox Smart cards** on Arduino platforms.  
It allows performing basic operations with the card, such as secure communication, retrieving card information, and simple cryptographic functions.

---

## Supported hardware

- **Cryptnox Smart cards** 💳
- **Arduino platforms** (e.g., Arduino Uno R4) with **PN532 NFC modules**

Get your cards here: [shop.cryptnox.com](https://shop.cryptnox.com)

---

## Dependencies

Before using `cryptnox-sdk-arduino`, you must install the following libraries via the **Arduino Library Manager**:

- **AESLib** (v2.3.6)
- **Adafruit_BusIO** (v1.17.4)
- **Adafruit_PN532** (v1.34.0)
- **Crypto** (v0.4.0)
- **micro-ecc** (v1.0.0)

---

## Adafruit_PN532 customization

> [!IMPORTANT]  
> To ensure compatibility with this SDK, you **must** modify Adafruit_PN532 library.
> 
> Locate in `libraries/Adafruit_PN532/Adafruit_PN532.cpp`:
> ```cpp
> #define PN532_PACKBUFFSIZ 64
> ```
> And replace it with:
> ```cpp
> #define PN532_PACKBUFFSIZ 255
> ```

## Installation

1. Download or clone this repository.  
2. Copy the `cryptnox-sdk-arduino` folder into your Arduino `libraries` directory.  
3. Restart the Arduino IDE to detect the library.

## Hardware setup

> [!CAUTION]
> Always double-check the wiring before powering the Arduino to prevent damage.

###  Arduino Uno R4 and PN532 NFC - SPI interface

| PN532 Pin | Arduino Pin | Wire Color |
|-----------|-------------|------------|
| VCC       | 5V          | Red        |
| GND       | GND         | Black      |
| SCK       | D13         | Blue       |
| MISO      | D12         | Green      |
| MOSI      | D11         | Yellow     |
| SS        | D10         | Violet     |


> [!IMPORTANT]  
> Make sure the I²C switches on the PN532 module are configured correctly for I²C communication:
>
> - **Switch 0** → HIGH  
> - **Switch 1** → LOW

<img width="800" alt="arduino_uno_pn532_spi" src="https://github.com/user-attachments/assets/87c2bba7-0376-45f8-a498-53b6468fc546" />


###  Arduino Uno R4 and PN532 NFC - I²C interface

| PN532 Pin | Arduino Pin | Wire Color |
|-----------|------------|------------|
| VCC       | 5V         | Red        |
| GND       | GND        | Black      |
| SDA       | A4         | Yellow     |
| SCL       | A5         | Blue       |
| RST       | D2         | Grey       |
| IRQ       | D3         | Violet     |

> [!IMPORTANT]  
> Make sure the I²C switches on the PN532 module are configured correctly for I²C communication:
>
> - **Switch 0** → LOW  
> - **Switch 1** → HIGH

<img width="800" alt="arduino_uno_pn532_i2c" src="https://github.com/user-attachments/assets/c040007c-b9a6-4bf7-861b-d6b28d195193" />

---

## Basic Example

```cpp
#include <AESLib.h>
#include <Adafruit_PN532.h>
#include <Crypto.h>
#include <uECC.h>

void setup() {
  Serial.begin(9600);
  Serial.println("Cryptnox-wallet initialization...");
}

void loop() {
  // Insert your card handling logic here
}
```

## Documentation

The generated documentation for this project is available [here](https://embarquech.github.io/cryptnox-sdk-arduino/).

## License

cryptnox-cli is dual-licensed:

- **LGPL-3.0** for open-source projects and proprietary projects that comply with LGPL requirements  
- **Commercial license** for projects that require a proprietary license without LGPL obligations (see COMMERCIAL.md for details)

For commercial inquiries, contact: contact@cryptnox.com
