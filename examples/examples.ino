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
#include "uECC.h"

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
 * The code demonstrates a granular approach to card processing,
 * showing each step of the secure channel establishment and card interaction.
 * Users can customize each step or add their own logic between operations.
 */
void loop() {
    
    /* Step 1: Check for ISO-DEP capable card (APDU-capable) */
    if (nfc.inListPassiveTarget()) {
        serialAdapter.println(F("ISO-DEP card detected"));
        
        /* Step 2: Select the Cryptnox application */
        if (wallet.selectApdu()) {
            serialAdapter.println(F("Cryptnox application selected"));
            
            /* Step 3: Get card certificate and extract ephemeral public key */
            uint8_t cardCertificate[146U];  /* GETCARDCERTIFICATE response: 148 bytes - 2 status words */
            uint8_t cardCertificateLength = 0U;
            uint8_t cardEphemeralPubKey[64U];
            
            if (wallet.getCardCertificate(cardCertificate, cardCertificateLength)) {
                serialAdapter.println(F("Card certificate received"));
                
                if (wallet.extractCardEphemeralKey(cardCertificate, cardEphemeralPubKey)) {
                    serialAdapter.println(F("Card ephemeral public key extracted"));
                    
                    /* Step 4: Open secure channel - get salt from card */
                    uint8_t salt[32U];
                    uint8_t clientPrivateKey[32U];
                    uint8_t clientPublicKey[64U];
                    const uECC_Curve_t* sessionCurve = uECC_secp256r1();
                    
                    if (wallet.openSecureChannel(salt, clientPublicKey, clientPrivateKey, sessionCurve)) {
                        serialAdapter.println(F("Secure channel opened - salt received"));
                        
                        /* Step 5: Mutual authentication - establish session keys */
                        CW_SecureSession session;
                        if (wallet.mutuallyAuthenticate(session, salt, clientPublicKey, clientPrivateKey, sessionCurve, cardEphemeralPubKey)) {
                            serialAdapter.println(F("Mutual authentication successful"));
                            serialAdapter.println(F("Session keys established"));
                            
                            /* Step 6: Verify PIN */
                            serialAdapter.println(F("Verifying PIN..."));
                            wallet.verifyPin(session);
                            
                            /* Step 7: Now you can perform secure operations */
                            serialAdapter.println(F("Card is ready for secure operations"));
                            
                            /* Example: Get card info */
                            serialAdapter.println(F("Getting card information..."));
                            wallet.getCardInfo(session);
                            
                            /* Securely clear session keys */
                            session.clear();
                            serialAdapter.println(F("Session cleared"));
                        } else {
                            serialAdapter.println(F("Mutual authentication failed"));
                        }
                    } else {
                        serialAdapter.println(F("Failed to open secure channel"));
                    }
                } else {
                    serialAdapter.println(F("Failed to extract card ephemeral key"));
                }
            } else {
                serialAdapter.println(F("Failed to get card certificate"));
            }
        } else {
            serialAdapter.println(F("Failed to select Cryptnox application"));
        }
    }
    else {
        /* Basic tag: read its UID */
        uint8_t uid[7];
        uint8_t uidLength;
        if (wallet.readUID(uid, uidLength)) {
            serialAdapter.print(F("Basic NFC tag detected - UID: "));
            for (uint8_t i = 0; i < uidLength; i++) {
                if (uid[i] < 16) serialAdapter.print(F("0"));
                serialAdapter.print(uid[i], HEX);
                serialAdapter.print(F(" "));
            }
            serialAdapter.println();
        }
    }
    
    /* Reset reader for next card detection */
    nfc.resetReader();
    
    /* Wait before next iteration */
    delay(1000);
}
