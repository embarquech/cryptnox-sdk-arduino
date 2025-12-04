#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

#include <Arduino.h>
#include "PN532Base.h"

#define RESPONSE_LENGHT_IN_BYTES 256
#define RANDOM_BYTES 8

/**
 * @brief High-level handler for Cryptnox ISO-DEP card.
 * 
 * Encapsulates APDU commands like SELECT and getCertificate.
 */
class CryptnoxWallet {
public:
    /**
     * @brief Construct a new CryptnoxWallet object.
     */
    CryptnoxWallet();

    /**
     * @brief Initialize the card (sends SELECT APDU).
     * 
     * @return true if the card responded correctly.
     */
    bool processCard();

    /**
     * @brief Retrieve certificate from card.
     * 
     * @param certBuffer Buffer to store certificate.
     * @param certLength Reference to variable to store length.
     * @return true if certificate successfully retrieved.
     */
    bool getCertificate(uint8_t* certBuffer, uint8_t &certLength);

private:
    PN532Base* nfc; /**< Underlying NFC interface */

    /**
     * @brief Sends a SELECT APDU to the NFC card to select a specific application.
     * 
     * Constructs a standard ISO/IEC 7816-4 SELECT APDU with predefined AID.
     * @return true if the APDU exchange succeeded.
     */
    bool selectApdu();

    /**
     * @brief Sends a GET CARD CERTIFICATE APDU to the NFC card.
     * 
     * Generates RANDOM_BYTES random bytes, constructs APDU, and sends it.
     * @return true if the APDU exchange succeeded.
     */
    bool getCardCertificate();
};

#endif
