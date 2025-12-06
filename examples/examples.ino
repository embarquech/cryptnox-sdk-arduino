/**
 * @file examples.ino
 * @brief Example demonstrating the use of CryptnoxWallet with a PN532 module on Arduino.
 *
 * This sketch initializes the I2C bus and the PN532 NFC reader using the
 * CryptnoxWallet class. It continuously detects NFC/ISO-DEP cards and
 * processes wallet-specific APDU commands.
 */

#include <Wire.h>
#include "CryptnoxWallet.h"

/**
 * @def PN532_IRQ
 * @brief IRQ pin of the PN532 module. Use -1 if unused.
 */
#define PN532_IRQ   -1

/**
 * @def PN532_RESET
 * @brief RESET pin of the PN532 module. Use -1 if unused.
 */
#define PN532_RESET -1

/**
 * @brief Instance of CryptnoxWallet using PN532 over I2C.
 */
CryptnoxWallet wallet(PN532_IRQ, PN532_RESET, &Wire);

/**
 * @brief Flag indicating whether the PN532 module was successfully initialized.
 */
bool pn532Available = false;

/**
 * @brief Arduino setup function.
 *
 * Initializes the serial port, I2C bus, and the PN532 module through
 * the CryptnoxWallet class. Sets a flag to indicate successful initialization.
 */
void setup() {
    Serial.begin(115200);
    Serial.println("CryptnoxWallet NFC/I2C Example");

    Wire.begin();

    pn532Available = wallet.begin();
    if (!pn532Available) {
        Serial.println("Warning: PN532 module not found! processCard() will not run.");
    } else {
        Serial.println("PN532 successfully initialized!");

        /* Check firmware printing result */
        if (!wallet.printPN532FirmwareVersion()) {
            Serial.println("Warning: Failed to read or print PN532 firmware version.");
        }
    }
}

/**
 * @brief Arduino main loop.
 *
 * Continuously checks for the presence of an NFC/ISO-DEP card and
 * processes wallet-specific APDU commands via CryptnoxWallet.
 * If the PN532 module failed to initialize, this function does nothing.
 */
void loop() {
    if (pn532Available == true) {
        (void)wallet.processCard();
    }

    delay(1000);
}
