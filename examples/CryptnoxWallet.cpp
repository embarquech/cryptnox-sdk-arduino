#include <Arduino.h>
#include <SHA512.h>
#include <AES.h>
#include "CryptnoxWallet.h"
#include "AESLib.h"

#define RESPONSE_GETCARDCERTIFICATE_IN_BYTES    148
#define RESPONSE_SELECT_IN_BYTES                 26
#define RESPONSE_OPENSECURECHANNEL_IN_BYTES      34
#define RESPONSE_STATUS_WORDS_IN_BYTES            2

#define OPENSECURECHANNEL_SALT_IN_BYTES            (RESPONSE_OPENSECURECHANNEL_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)
#define GETCARDCERTIFICATE_IN_BYTES                (RESPONSE_GETCARDCERTIFICATE_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)

#define RANDOM_BYTES                              8
#define COMMON_PAIRING_DATA                        "Cryptnox Basic CommonPairingData"
#define CLIENT_PRIVATE_KEY_SIZE                  32
#define CLIENT_PUBLIC_KEY_SIZE                   64
#define CARDEPHEMERALPUBKEY_SIZE                 64
#define AES_BLOCK_SIZE                           16
#define AES_TEST_DATA_SIZE                       32
#define INPUT_BUFFER_LIMIT                         (128 + 1)

/* Main NFC handler:
 * - If ISO-DEP card detected → select app, request certificate, open secure channel.
 * - Otherwise → try reading UID of simple NFC tag.
 */
bool CryptnoxWallet::processCard() {
    bool ret = false;
    /* Local response buffer */
    uint8_t cardCertificate[GETCARDCERTIFICATE_IN_BYTES];
    uint8_t cardCertificateLength = 0;
    uint8_t openSecureChannelSalt[OPENSECURECHANNEL_SALT_IN_BYTES];

    uint8_t clientPrivateKey[32];
    uint8_t clientPublicKey[64];
    const uECC_Curve_t * sessionCurve = uECC_secp256r1();

    uint8_t cardEphemeralPubKey[CARDEPHEMERALPUBKEY_SIZE];

    /* Check for ISO-DEP capable target (APDU-capable card) */
    if (driver.inListPassiveTarget()) {
        /* Try selecting Cryptnox app */
        if (selectApdu()) {
            /* Get certificate and establish secure channel */
            getCardCertificate(cardCertificate, cardCertificateLength);
            extractCardEphemeralKey(cardCertificate, cardEphemeralPubKey);
            openSecureChannel(openSecureChannelSalt, clientPublicKey, clientPrivateKey, sessionCurve);
            mutuallyAuthenticate(openSecureChannelSalt, clientPublicKey, clientPrivateKey, sessionCurve, cardEphemeralPubKey);
            ret = true;
        }
    }
    else {
        /* Basic tag: read its UID */
        uint8_t uid[7];
        uint8_t uidLength;
        if (driver.readUID(uid, uidLength)) {
            Serial.print(F("Card UID: "));
            for (uint8_t i = 0; i < uidLength; i++) {
                if (uid[i] < 16) Serial.print(F("0"));
                Serial.print(uid[i], HEX);
                Serial.print(F(" "));
            }
            Serial.println();
        }
    }

    /* Reset reader in for the card to be detected by inListPassiveTarget again */
    driver.resetReader();
    
    return ret;
}

/* Simple forward to PN532 driver for UID read */
bool CryptnoxWallet::readUID(uint8_t* uidBuffer, uint8_t &uidLength) {
    return driver.readUID(uidBuffer, uidLength);
}

/* Print PN532 firmware version via driver */
bool CryptnoxWallet::printPN532FirmwareVersion() {
    return driver.printFirmwareVersion();
}

/* SELECT APDU to activate Cryptnox application */
bool CryptnoxWallet::selectApdu() {
    bool ret = false;

    /* Application AID selection command */
    uint8_t selectApdu[] = {
        0x00, /* CLA  : ISO interindustry */
        0xA4, /* INS  : SELECT */
        0x04, /* P1   : Select by name */
        0x00, /* P2   : First or only occurrence */
        0x07, /* Lc   : Length of AID */
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12  /* AID */
    };

    /* Print APDU */
    printApdu(selectApdu, sizeof(selectApdu));

    /* Response buffer on stack */
    uint8_t response[RESPONSE_SELECT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    Serial.println(F("Sending Select APDU..."));

    /* Send SELECT command */
    if (driver.sendAPDU(selectApdu, sizeof(selectApdu), response, responseLength)) {
        if (checkStatusWord(response,responseLength, 0x90, 0x00)) {
            Serial.println(F("APDU exchange successful!"));
            ret = true;
        } else {
            Serial.println(F("APDU SW1/SW2 not expected. Error."));
        }
    } else {
        Serial.println(F("APDU select failed."));
    }

    return ret;
}

/**
 * @brief Retrieves the card's ephemeral public key with a GET CARD CERTIFICATE APDU.
 *
 * Sends a GET CARD CERTIFICATE command to the card, validates the response,
 * and extracts the ephemeral EC P-256 public key used for ECDH in the secure channel.
 *
 * | Field                      | Size                | Description                                                               |
 * |----------------------------|---------------------|---------------------------------------------------------------------------|
 * | 'C'                        | 1 byte              | Certificate format identifier                                             |
 * | Nonce                      | 8 bytes (64 bits)   | Random challenge sent by the client                                       |
 * | Session Public Key         | 65 bytes            | Card's ephemeral EC P-256 public key for ECDH                             |
 * | ASN.1 DER Signature        | 70–72 bytes         | Signature over the previous fields using the card's permanent private key |
 * 
 * @param[out] cardEphemeralPubKey Buffer to store the 65-byte card ephemeral public key.
 * @param[in,out] cardEphemeralPubKeyLength Input: size of the buffer; Output: actual key length (65 bytes).
 * @return true if the APDU exchange and key extraction succeeded, false otherwise.
 */
bool CryptnoxWallet::getCardCertificate(uint8_t* cardCertificate, uint8_t &cardCertificateLength) {
    bool ret = false;
    uint8_t getCardCertificateResponse[RESPONSE_GETCARDCERTIFICATE_IN_BYTES];
    uint8_t getCardCertificateResponseLength = sizeof(getCardCertificateResponse);
    uint8_t randomBytes[RANDOM_BYTES];

    if (cardCertificate != nullptr) {
        /* APDU template (last 8 bytes replaced by random nonce) */
        uint8_t getCardCertificateApdu[] = {
            0x80,  /* CLA */
            0xF8,  /* INS : GET CARD CERTIFICATE */
            0x00,  /* P1 */
            0x00,  /* P2 */
            0x08,  /* Lc : 8 bytes nonce */
        };

        /* Generate 8 random bytes */
        uECC_RNG(randomBytes, RANDOM_BYTES);

        /* Final APDU = header + 8 random bytes */
        uint8_t fullApdu[sizeof(getCardCertificateApdu) + RANDOM_BYTES];
        memcpy(fullApdu, getCardCertificateApdu, sizeof(getCardCertificateApdu));
        memcpy(fullApdu + sizeof(getCardCertificateApdu), randomBytes, RANDOM_BYTES);

        /* Print APDU */
        printApdu(fullApdu, sizeof(fullApdu));

        Serial.println(F("Sending getCardCertificate APDU..."));

        /* Send APDU */
        if (driver.sendAPDU(fullApdu, sizeof(fullApdu), getCardCertificateResponse, getCardCertificateResponseLength)) {
            if (checkStatusWord(getCardCertificateResponse, getCardCertificateResponseLength, 0x90, 0x00)) {
                /* Remove status word from answer */
                cardCertificateLength = getCardCertificateResponseLength - RESPONSE_STATUS_WORDS_IN_BYTES;

                /* Copy only the useful data (the salt) into the buffer */
                memcpy(cardCertificate, getCardCertificateResponse, cardCertificateLength);

                Serial.println(F("APDU exchange successful!"));    
                ret = true;
            } else {
                Serial.println(F("APDU SW1/SW2 not expected. Error."));
            }
        } else {
            Serial.println(F("APDU getCardCertificate failed."));
        }
    }
    
    return ret;
}

/**
 * @brief Retrieves the initial 32-byte salt from the card for starting a secure channel.
 *
 * This function sends the APDU command to the card to get the session salt, which is
 * required for the subsequent key derivation in the secure channel setup.
 *
 * @param[inout] salt Pointer to a 32-byte buffer where the card-provided salt will be stored.
 * @param[inout] clientPublicKey Buffer to store the client's generated 64-byte public key.
 * @param[inout] clientPrivateKey Buffer to store the client's generated 32-byte private key.
 * @param[in] sessionCurve Pointer to the uECC curve object used for key generation (e.g., uECC_secp256r1()).
 * @return true if the APDU exchange succeeded and the salt was retrieved, false otherwise.
 */
bool CryptnoxWallet::openSecureChannel(uint8_t* salt, uint8_t* sessionPublicKey, uint8_t* sessionPrivateKey, const uECC_Curve_t* sessionCurve) {
    bool ret = false;

    /* ECC setup and random generation */
    uECC_set_rng(&uECC_RNG);

    /* Generate keypair */
    bool eccSuccess = uECC_make_key(sessionPublicKey, sessionPrivateKey, sessionCurve);

    /* Abort if ECC fails */
    if (!eccSuccess) {
        Serial.println(F("ECC key generation failed."));
    }
    else {
        /* APDU header for OPEN SECURE CHANNEL */
        uint8_t opcApduHeader[] = {
            0x80,  /* CLA */
            0x10,  /* INS : OPEN SECURE CHANNEL */
            0x00,  /* P1 : pairing slot index */
            0x00,  /* P2 */
            0x41,  /* Lc : 1 format byte + 64 public key bytes */
            0x04   /* ECC uncompressed public key format */
        };

        /* Construct final APDU */
        uint8_t fullApdu[sizeof(opcApduHeader) + CLIENT_PUBLIC_KEY_SIZE];
        memcpy(fullApdu, opcApduHeader, sizeof(opcApduHeader));
        memcpy(fullApdu + sizeof(opcApduHeader), sessionPublicKey, CLIENT_PUBLIC_KEY_SIZE);

        /* Response buffer */
        uint8_t response[RESPONSE_OPENSECURECHANNEL_IN_BYTES];
        uint8_t responseLength = sizeof(response);

        /* Print APDU */
        printApdu(fullApdu, sizeof(fullApdu));

        Serial.println(F("Sending OpenSecureChannel APDU..."));

        /* Send OPC request */
        if (driver.sendAPDU(fullApdu, sizeof(fullApdu), response, responseLength)) {
            if (checkStatusWord(response, responseLength, 0x90, 0x00)) {
                if (responseLength == RESPONSE_OPENSECURECHANNEL_IN_BYTES) {
                    /* Remove status word from answer */
                    size_t dataLength = OPENSECURECHANNEL_SALT_IN_BYTES;

                    /* Copy only the useful data (the salt) into the buffer */
                    memcpy(salt, response, dataLength);

                    Serial.println(F("APDU exchange successful!"));    
                    ret = true;
                } 
                else {
                    Serial.println(F("Unexpected response size."));
                }
            } else {
                Serial.println(F("APDU SW1/SW2 not expected. Error."));
            }
        } else {
            Serial.println(F("APDU exchange failed."));
        }
    }

    return ret;
}

/**
 * @brief Performs the ECDH-based mutual authentication step of the secure channel.
 *
 * This function computes the shared secret between the client's private key
 * and the card's ephemeral public key using the specified ECC curve.
 *
 * @param[in] salt Pointer to the 32-byte salt received from the card.
 * @param[in] clientPublicKey Pointer to the 64-byte client public key.
 * @param[in] clientPrivateKey Pointer to the 32-byte client private key.
 * @param[in] sessionCurve Pointer to the ECC curve (e.g., uECC_secp256r1()).
 * @param[in] cardEphemeralPubKey Pointer to the 65-byte card ephemeral public key ('0x04' prefix + X||Y).
 * @return true if the shared secret was successfully generated, false otherwise.
 */
bool CryptnoxWallet::mutuallyAuthenticate(uint8_t* salt, uint8_t* clientPublicKey, uint8_t* clientPrivateKey, const uECC_Curve_t* sessionCurve, uint8_t* cardEphemeralPubKey) {
    bool ret = false;
    uint8_t sharedSecret[32];
    uint8_t concat[32 + sizeof(COMMON_PAIRING_DATA) - 1 + 32]; /* sharedSecret || pairingKey || salt */
    uint8_t sha512Output[64];
    uint8_t aesKey[32];
    uint8_t macKey[32];
    size_t pairingKeyLen;
    size_t concatLen;
    AESLib aesLib;

    /* Generate ECDH shared secret with card ephemeral public key and client private key */
    if (uECC_shared_secret(cardEphemeralPubKey, clientPrivateKey, sharedSecret, sessionCurve) == 0) {
        Serial.println(F("ECDH shared secret generation failed!"));
        return false;
    }
    else {
        Serial.println(F("ECDH shared secret generated."));

        /* Concatenate sharedSecret, pairingKey, and salt */
        pairingKeyLen = sizeof(COMMON_PAIRING_DATA) - 1U; /* exclude null terminator */
        concatLen = 32U + pairingKeyLen + 32U;

        memcpy(concat, sharedSecret, 32U); /* copy sharedSecret */
        memcpy(concat + 32U, COMMON_PAIRING_DATA, pairingKeyLen); /* copy pairingKey */
        memcpy(concat + 32U + pairingKeyLen, salt, 32U); /* copy salt */

        /* Calculate SHA-512 over concatenated buffer */
        SHA512 sha;
        sha.update(concat, concatLen);
        sha.finalize(sha512Output, sizeof(sha512Output));

        Serial.println(F("SHA-512 calculated."));

        /* Split SHA-512 output into Kenc and Kmac */
        memcpy(aesKey, sha512Output, 32U);       /* first 32 bytes for encryption key */
        memcpy(macKey, sha512Output + 32U, 32U); /* last 32 bytes for MAC key */

        Serial.println(F("Kenc and Kmac derived."));

        /* Set shared iv and mac_iv by client and smartcard */
        uint8_t iv_opc[N_BLOCK];
        memset(iv_opc, 0x01, N_BLOCK);
        uint8_t mac_iv[N_BLOCK];
        memset(mac_iv, 0x00, N_BLOCK);

        /* Padded data */
        uint8_t RNG_data[32] = { 0X7, 0X72, 0X30, 0XB, 0XDC, 0X82, 0X58, 0XEC, 0X32, 0X59, 0XCE, 0X38, 0X69, 0X24, 0X1B, 0X59, 0XFB, 0X10, 0X7B, 0X92, 0X10, 0XF2, 0X6E, 0X1F, 0X5E, 0X37, 0X66, 0X6A, 0XC6, 0X55, 0XB5, 0XEF};

        /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
        aesLib.set_paddingmode(paddingMode::Bit);
        unsigned char ciphertextOPC[2 * INPUT_BUFFER_LIMIT] = { 0 };
        uint8_t paddedLength = aesLib.get_cipher_length(sizeof(RNG_data));
        uint16_t cipherLength;
        Serial.print("paddedLength = ");
        Serial.println(paddedLength);
        cipherLength = aesLib.encrypt((byte*)RNG_data, sizeof(RNG_data), ciphertextOPC, aesKey, sizeof(aesKey), iv_opc);
        Serial.print("cipherlength = ");
        Serial.println(cipherLength);

        Serial.println(" Encrypted ------------------ ");
        for (int i = 0; i < cipherLength; i++) {
            Serial.print(ciphertextOPC[i], HEX);
        }

        Serial.println();

        uint8_t opcApduHeader[] = { 0x80, 0x11, 0x00, 0x00, paddedLength + 16 };
        uint8_t MAC_apduHeader[] = { 0x80, 0x11, 0x00, 0x00, paddedLength + 16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        uint8_t MAC_data_length = sizeof(MAC_apduHeader) + cipherLength;
        uint8_t MAC_data[MAC_data_length];
        uint8_t* buffMAC_data = MAC_data;

        memcpy(buffMAC_data, MAC_apduHeader, sizeof(MAC_apduHeader));
        buffMAC_data += sizeof(MAC_apduHeader);
        memcpy(buffMAC_data, ciphertextOPC, cipherLength);

        Serial.println(" MAC data ------------------ ");
        for (int i = 0; i < MAC_data_length; i++) {
            Serial.print(MAC_data[i], HEX);
        }
        Serial.println();

        unsigned char ciphertextMACLong[2 * INPUT_BUFFER_LIMIT] = { 0 };
        /* Set no padding */
        aesLib.set_paddingmode(paddingMode::Null);
        uint16_t encryptedLengthMAC = aesLib.encrypt((byte*)MAC_data, MAC_data_length, ciphertextMACLong, macKey, sizeof(macKey), mac_iv);

        uint8_t MACpaddedLength = aesLib.get_cipher_length(MAC_data_length);
        Serial.println("MACpaddedLength: ");
        Serial.println(MACpaddedLength);

        uint8_t MAC_value[16];
        uint8_t firstSliceLength = encryptedLengthMAC - 16;

        for (int i = firstSliceLength; i < encryptedLengthMAC; i++) {
            MAC_value[i - firstSliceLength] = ciphertextMACLong[i];
            Serial.print(ciphertextMACLong[i], HEX);
        }

        Serial.println();
        /* 5 + 16 + 48 = 69 */
        uint8_t apduOpcLength = sizeof(opcApduHeader) + sizeof(MAC_value) + cipherLength;
        uint8_t sendApduOpc[apduOpcLength];
        uint8_t* buff_send_apdu = sendApduOpc;
        Serial.println("apduOpcLength: ");
        Serial.println(apduOpcLength);
        Serial.println("MAC_value len: ");
        Serial.println(sizeof(MAC_value));
        Serial.println("cipherLength len: ");
        Serial.println(cipherLength);

        /* OPC HEADER || MAC value || ciphertextOPC */
        memcpy(buff_send_apdu, opcApduHeader, sizeof(opcApduHeader));
        buff_send_apdu += sizeof(opcApduHeader);
        memcpy(buff_send_apdu, MAC_value, sizeof(MAC_value));
        buff_send_apdu += sizeof(MAC_value);
        memcpy(buff_send_apdu, ciphertextOPC, cipherLength);

        uint8_t res_send_opc[255];
        uint8_t sendOpcResLength = sizeof(res_send_opc);

        Serial.println("send APDU");

        for (int i = 0; i < sizeof(sendApduOpc); i++) {
            Serial.print(sendApduOpc[i], HEX);
        }
        Serial.println();

        if (driver.sendAPDU(sendApduOpc, sizeof(sendApduOpc), res_send_opc, sendOpcResLength)) {
            Serial.print("responseLength: ");
            Serial.println(sendOpcResLength);
            Serial.println("OpenSecureChannel success.");
        } else {
            Serial.println(F("APDU exchange failed."));
        }

        ret = true; 
    }

    return ret;
}

/**
 * @brief RNG callback used by the micro-ecc library.
 * 
 * Fills the provided buffer with cryptographically random bytes.
 * @param dest Pointer to the buffer to fill.
 * @param size Number of bytes to generate.
 * @return 1 on success.
 */
int CryptnoxWallet::uECC_RNG(uint8_t *dest, unsigned size) {
    if (dest != nullptr) {
        /* Seed the RNG once; ideally done once in setup() */
        static bool seeded = false;
        if (seeded == false) {
            randomSeed(analogRead(0));
            seeded = true;
        }

        for (uint16_t i = 0u; i < size; i++) {
            dest[i] = (uint8_t)random(0, 256);
        }
    }

    return 1;
}

/**
 * @brief Print an APDU in hexadecimal format to Serial for debugging.
 * 
 * Each byte is printed as 0xXX. Lines wrap every 16 bytes for readability.
 * @param apdu Pointer to the APDU byte array.
 * @param length Number of bytes in the APDU.
 * @param label Optional label to prepend (default: "APDU to send").
 */
void CryptnoxWallet::printApdu(const uint8_t* apdu, uint8_t length, const char* label) {
    Serial.print(label);
    Serial.print(F(": "));
    Serial.println();
    for (uint8_t i = 0; i < length; i++) {
        Serial.print("0x");
        if (apdu[i] < 16) Serial.print("0");
        Serial.print(apdu[i], HEX);
        Serial.print(" ");
        
        /* Wrap line every 16 bytes */
        if ((i + 1) % 16 == 0 && (i + 1) != length) Serial.println();
    }
    
    Serial.println();
}

/**
 * @brief Checks the status word (SW1/SW2) at the end of an APDU response.
 * 
 * @param response        Pointer to the APDU response buffer.
 * @param responseLength  Actual length of the response buffer.
 * @param sw1Expected     Expected value for SW1 (e.g., 0x90).
 * @param sw2Expected     Expected value for SW2 (e.g., 0x00).
 * @return true if the last two bytes match SW1/SW2, false otherwise.
 */
bool CryptnoxWallet::checkStatusWord(const uint8_t* response, uint8_t responseLength, uint8_t sw1Expected, uint8_t sw2Expected) {
    bool ret = false;

    if (response == nullptr || responseLength < 2) {
        Serial.println(F("checkStatusWord: response too short."));
        ret = false;
    }
    else {
        uint8_t sw1 = response[responseLength - 2];
        uint8_t sw2 = response[responseLength - 1];

        Serial.print(F("Received SW1/SW2: "));
        Serial.print(F("0x"));
        if (sw1 < 16) Serial.print("0");
        Serial.print(sw1, HEX);
        Serial.print(F(" "));
        Serial.print(F("0x"));
        if (sw2 < 16) Serial.print("0");
        Serial.println(sw2, HEX);

        if ((sw1 == sw1Expected) && (sw2 == sw2Expected)) {
            ret = true;
        }
        else {
            ret = false;
        }
    }

    return ret;
}

/**
 * @brief Extracts the card's ephemeral EC P-256 public key from the certificate.
 *
 * Certificate layout (0-based):
 * | Field                   | Size       | Offset |
 * |-------------------------|-----------|--------|
 * | 'C'                     | 1 byte    | 0      |
 * | Nonce                   | 8 bytes   | 1–8    |
 * | Session Public Key      | 65 bytes  | 9–73   |
 * | ASN.1 DER Signature     | 70–72 bytes | 74+  |
 *
 * @param[in]  cardCertificate        Pointer to the full card certificate response.
 * @param[out] cardEphemeralPubKey    Buffer to store **64 bytes** (X||Y coordinates only, no 0x04 prefix)
 *                                    for use with uECC_shared_secret. Must be at least 64 bytes.
 * @param[out] fullEphemeralPubKey65  Optional buffer to store **65 bytes** including the 0x04 prefix.
 *                                    Can be nullptr if not needed.
 */
bool CryptnoxWallet::extractCardEphemeralKey(const uint8_t* cardCertificate, uint8_t* cardEphemeralPubKey, uint8_t* fullEphemeralPubKey65) {
    bool ret = false;

    Serial.print(F("Full Ephemeral Public Key (65 bytes):"));
    Serial.println();
    if ((cardCertificate == nullptr) || (cardEphemeralPubKey == nullptr)) {
        ret = false; // invalid input
    }
    else {
        const uint8_t keyStart = 1u + 8u; /* skip 'C' and nonce */
        const uint8_t fullKeyLength = 65u; /* includes 0x04 prefix */
        uint8_t i;

        for (i = 0u; i < fullKeyLength; i++) {
            uint8_t b = cardCertificate[keyStart + i];

            /* Copy full key including prefix if buffer provided */
            if (fullEphemeralPubKey65 != nullptr) {
                fullEphemeralPubKey65[i] = b;
            }

            /* Skip the first byte (0x04 prefix) for ECDH */
            if (i > 0u) {
                cardEphemeralPubKey[i - 1u] = b;
            }

            /* Print hex to Serial for debugging */
            Serial.print("0x");
            if (b < 0x10u) {
                Serial.print('0');
            }
            Serial.print(b, HEX);
            Serial.print(' ');

            /* Wrap line every 16 bytes */
            if ((i + 1) % 16 == 0 && (i + 1) != fullKeyLength) Serial.println();
        }

        Serial.println();
    }

    return ret;
}
