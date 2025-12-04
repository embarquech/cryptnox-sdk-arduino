#include "CardHandler.h"
#include <Arduino.h>

/** @brief Length of the response buffer in bytes */
#define RESPONSE_LENGHT_IN_BYTES    64

/** @brief Number of random bytes to generate for card certificate */
#define RANDOM_BYTES    8  

/**
 * @brief Construct a new CardHandler object.
 * 
 * @param nfcInterface Pointer to a PN532Base instance for NFC communication.
 */
CardHandler::CardHandler(PN532Base* nfcInterface)
    : nfc(nfcInterface) {}

/**
 * @brief Initialize the card by sending a SELECT APDU and retrieving a certificate.
 * 
 * @return true if the card was successfully initialized, false otherwise.
 */
bool CardHandler::init() {
    bool ret = false;

    if (selectApdu()) {
        Serial.println("Sending SELECT APDU...");
        getCardCertificate();
        ret = true;
    } else {
        Serial.println("Error with SELECT APDU");
        ret = false;
    }

    return ret;
}

/**
 * @brief Retrieve the card certificate.
 * 
 * @param certBuffer Pointer to buffer to store the certificate (currently unused).
 * @param certLength Reference to variable to store certificate length (currently unused).
 * @return true if the certificate retrieval succeeded, false otherwise.
 */
bool CardHandler::getCertificate(uint8_t* certBuffer, uint8_t &certLength) {
    return getCardCertificate();
}

/**
 * @brief Send a SELECT APDU to select a specific application on the card.
 * 
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool CardHandler::selectApdu() {
    bool ret = false;

    uint8_t selectApdu[] = { 
        0x00, 0xA4, 0x04, 0x00, 0x07, 
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12
    };

    uint8_t response[RESPONSE_LENGHT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    Serial.println("Sending SELECT APDU...");

    if (nfc->sendAPDU(selectApdu, sizeof(selectApdu), response, responseLength)) {
        ret = true;
    } else {
        Serial.println("APDU exchange failed!");
    }

    return ret;
}

/**
 * @brief Send a GET CARD CERTIFICATE APDU with random bytes.
 * 
 * Generates RANDOM_BYTES random bytes, sends the APDU to the card, 
 * and prints the APDU and response for debugging.
 * 
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool CardHandler::getCardCertificate() {
    bool ret = false;

    uint8_t getCardCertificateApdu[] = { 
        0x80, 0xF8, 0x00, 0x00, 0x08, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t response[RESPONSE_LENGHT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    /** @brief Seed random generator */
    randomSeed(analogRead(0));

    /** @brief Fill the last RANDOM_BYTES bytes with random values */
    for (int i = sizeof(getCardCertificateApdu) - RANDOM_BYTES; i < sizeof(getCardCertificateApdu); i++) {
        getCardCertificateApdu[i] = random(0, 256);
    }

    /** @brief Print APDU for verification */
    Serial.print("APDU to send: ");
    for (int i = 0; i < sizeof(getCardCertificateApdu); i++) {
        if (getCardCertificateApdu[i] < 16) Serial.print("0");
        Serial.print(getCardCertificateApdu[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    Serial.println("Sending APDU...");

    if (nfc->sendAPDU(getCardCertificateApdu, sizeof(getCardCertificateApdu), response, responseLength)) {
        Serial.println("APDU exchange successful!");
        ret = true;
    } else {
        Serial.println("APDU exchange failed!");
    }

    return ret;
}
