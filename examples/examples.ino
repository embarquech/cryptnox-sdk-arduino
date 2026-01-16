/**
 * @file examples.ino
 * @brief Example demonstrating the use of CryptnoxWallet with a PN532 module on Arduino.
 *
 * This sketch initializes the I2C bus and the PN532 NFC reader using the
 * CryptnoxWallet class. It continuously detects NFC/ISO-DEP cards and
 * processes wallet-specific APDU commands.
 */

#include "PN532Adapter.h"
#include "CryptnoxWallet.h"
#include "ArduinoSerialAdapter.h"

/**
 * @def PN532_SS
 * @brief Slave select pin of the PN532 module. Set to -1 if not used.
 */
#define PN532_SS   (10U)

ArduinoSerialAdapter serialAdapter;
PN532Adapter nfc(serialAdapter, PN532_SS, &SPI);
CryptnoxWallet wallet(nfc, serialAdapter);

/**
 * @brief Arduino setup function.
 *
 * Initializes the serial port for debugging and the I2C bus.
 * The actual PN532 initialization is performed later in loop().
 */
void setup() {
    serialAdapter.begin(115200);
    
    /* Arduino R4: Wait 1s to get Serial ready */
    delay(1000);

    /* Initialize SPI bus */
    SPI.begin();

    /* Initialize the PN532 module */
    if (wallet.begin()) {
        serialAdapter.println(F("PN532 initialized"));
        wallet.printPN532FirmwareVersion();
    } else {
        serialAdapter.println(F("PN532 init failed"));
        /* Halt program if initialization fails */
        while(1);
    }
}

/**
 * @brief Arduino main loop.
 *
 * The CryptnoxWallet object is declared static so that it persists
 * between iterations. The PN532 module is initialized only once
 * using a static 'initialized' flag.
 *
 * On each loop iteration, the code checks for the presence of a
 * passive NFC/ISO-DEP card and processes wallet APDU commands.
 */
void loop() {
    
    /* Process any detected NFC card */
    (void)wallet.processCard();

    /* Wait 1 second before next loop iteration */
    delay(1000);
}
