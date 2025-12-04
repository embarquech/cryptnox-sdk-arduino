/**
 * @file main.ino
 * @brief Arduino sketch for interacting with PN532 NFC module via I2C.
 * 
 * This code initializes the PN532 module, reads its firmware version,
 * selects an application on a card via APDU, and retrieves a random
 * 8-byte certificate from the card. It supports both ISO-DEP and MIFARE/NTAG cards.
 */

#include <Arduino.h>
#include "PN532I2C.h"
#include "CardHandler.h"

/** @brief I2C SDA pin used for PN532 communication */
#define SDA_PIN A4 

/** @brief I2C SCL pin used for PN532 communication */
#define SCL_PIN A5 

/**
 * @brief Pointer to the PN532 NFC/RFID interface.
 * 
 * Uses the abstract base class PN532Base to allow swapping interfaces easily.
 */
PN532Base* nfc = new PN532I2C(SDA_PIN, SCL_PIN);

/** @brief CardHandler instance for Cryptnox card operations */
CardHandler* card = new CardHandler(nfc);

/**
 * @brief Arduino setup function.
 * 
 * Initializes serial communication, starts the PN532 module,
 * and reads its firmware version. If the PN532 module fails to
 * initialize, the program halts in an infinite loop.
 */
void setup() {
    Serial.begin(115200);

    /** @brief Initialize the PN532 module */
    if (!nfc->begin()) {
        Serial.println("Failed to start PN532!");
        while (1);
    }

    Serial.println("PN532 ready");
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
    uint8_t uid[7];
    uint8_t uidLength;

    /** @brief ISO-DEP card detected */
    if (nfc->inListPassiveTarget()) {
        /** @brief Initialize the card (SELECT APDU) */
        if (card->init()) {
            Serial.println("Card initialized (SELECT APDU sent)");
        } else {
            Serial.println("Card init failed");
        }

    /** @brief Fallback MIFARE/NTAG card detected */
    } else if (nfc->readUID(uid, uidLength)) {
        Serial.print("Card UID: ");
        for (int i = 0; i < uidLength; i++) Serial.print(uid[i], HEX);
        Serial.println();
    }

    delay(1000);
}
