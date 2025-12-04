/**
 * @file main.ino
 * @brief Arduino sketch for interacting with PN532 NFC module via I2C.
 * 
 * This code initializes the PN532 module, reads its firmware version,
 * selects an application on a card via APDU, and retrieves a random
 * 8-byte certificate from the card. It supports both ISO-DEP and MIFARE/NTAG cards.
 */

#include <Arduino.h>
#include "CryptnoxWallet.h"

/** @brief CardHandler instance for Cryptnox card operations */
CryptnoxWallet* wallet;

/**
 * @brief Arduino setup function.
 * 
 * Initializes serial communication, starts the PN532 module,
 * and reads its firmware version. If the PN532 module fails to
 * initialize, the program halts in an infinite loop.
 */
void setup() {
    Serial.begin(115200);

    /** @brief Create CardHandler and initialize the card */
    wallet = new CryptnoxWallet();
}

/**
 * @brief Arduino main loop function.
 * 
 * Continuously checks for NFC cards. If an ISO-DEP card is detected,
 * it sends the selectApdu() and getCardCertificate() commands.
 * If a fallback MIFARE/NTAG card is detected, it reads and prints
 * the UID to Serial.
 */
void loop() {
    /** @brief ISO-DEP card detected */
    (void)wallet->processCard();

    delay(1000);
}
