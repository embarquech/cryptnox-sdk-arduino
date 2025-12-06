#include "CryptnoxWallet.h"
#include <Arduino.h>

/**
 * @brief Detects an ISO-DEP or passive NFC card and processes wallet APDUs.
 *
 * If an ISO-DEP card is detected, the SELECT APDU is sent and the certificate
 * is retrieved. If only a passive card is detected, the UID is printed.
 *
 * @return true if a card was successfully processed, false otherwise.
 */
bool CryptnoxWallet::processCard() {
    bool ret = false;
    uint8_t uid[7];
    uint8_t uidLength;

    if (driver.inListPassiveTarget()) {
        if (selectApdu()) {
            Serial.println("Card selected. Retrieving certificate...");
            getCardCertificate();
            ret = true;
        }
    }
    else if (driver.readUID(uid, uidLength)) {
        Serial.print("Card UID: ");
        for (uint8_t i = 0; i < uidLength; i++) {
            if (uid[i] < 16) Serial.print("0");
            Serial.print(uid[i], HEX);
            Serial.print(" ");
        }
        Serial.println();
    }

    return ret;
}

/**
 * @brief Reads the UID of a detected card via the underlying driver.
 *
 * @param uidBuffer Pointer to buffer to store the UID.
 * @param uidLength Reference to variable to store the UID length.
 * @return true if a UID was read successfully, false otherwise.
 */
bool CryptnoxWallet::readUID(uint8_t* uidBuffer, uint8_t &uidLength) {
    return driver.readUID(uidBuffer, uidLength);
}

/**
 * @brief Print detailed firmware information of the PN532 module.
 *
 * Retrieves the firmware version, parses IC type, major/minor versions,
 * and supported features, then prints all details to the Serial console.
 *
 * @return true if the PN532 module was detected and information printed, false otherwise.
 */
bool CryptnoxWallet::printPN532FirmwareVersion() {
    return driver.printFirmwareVersion();
}

/**
 * @brief Sends the SELECT APDU to select the wallet application.
 *
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool CryptnoxWallet::selectApdu() {
    bool ret = false;

    uint8_t selectApdu[] = { 
        0x00, 0xA4, 0x04, 0x00, 0x07, 
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12
    };

    uint8_t response[RESPONSE_LENGTH_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    Serial.println("Sending Select APDU...");

    if (driver.sendAPDU(selectApdu, sizeof(selectApdu), response, responseLength)) {
        ret = true;
    } else {
        Serial.println("APDU select failed.");
    }

    return ret;
}

/**
 * @brief Sends the GET CARD CERTIFICATE APDU with random bytes for challenge.
 *
 * Generates RANDOM_BYTES random bytes, sends the APDU to the card, and prints
 * the APDU and response for debugging.
 *
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool CryptnoxWallet::getCardCertificate() {
    bool ret = false;

    uint8_t getCardCertificateApdu[] = { 
        0x80, 0xF8, 0x00, 0x00, 0x08, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t response[RESPONSE_LENGTH_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    randomSeed(analogRead(0));
    for (int i = sizeof(getCardCertificateApdu) - RANDOM_BYTES; i < sizeof(getCardCertificateApdu); i++) {
        getCardCertificateApdu[i] = random(0, 256);
    }

    Serial.print("APDU to send: ");
    for (int i = 0; i < sizeof(getCardCertificateApdu); i++) {
        if (getCardCertificateApdu[i] < 16) Serial.print("0");
        Serial.print(getCardCertificateApdu[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    Serial.println("Sending getCardCertificate APDU...");

    if (driver.sendAPDU(getCardCertificateApdu, sizeof(getCardCertificateApdu), response, responseLength)) {
        Serial.println("APDU exchange successful!");
        ret = true;
    } else {
        Serial.println("APDU getCardCertificate failed.");
    }

    return ret;
}
