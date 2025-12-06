#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

#include "PN532Base.h"
#include <Arduino.h>

#define RESPONSE_LENGTH_IN_BYTES 64
#define RANDOM_BYTES 8

/**
 * @class CryptnoxWallet
 * @brief High-level interface for interacting with a PN532-based wallet.
 *
 * This class encapsulates NFC card operations specific to the Cryptnox wallet,
 * including sending APDUs, retrieving the card certificate, and reading the UID.
 * It supports all bus types provided by Adafruit_PN532 (I2C, SPI, Software SPI, UART)
 * via constructor overloading.
 */
class CryptnoxWallet {
public:
    /**
     * @brief Construct a CryptnoxWallet over I2C.
     *
     * @param irq Pin number for PN532 IRQ (use -1 if unused).
     * @param reset Pin number for PN532 RESET (use -1 if unused).
     * @param theWire TwoWire instance (default is &Wire).
     */
    CryptnoxWallet(uint8_t irq, uint8_t reset, TwoWire *theWire = &Wire)
        : driver(irq, reset, theWire) {}

    /**
     * @brief Construct a CryptnoxWallet over hardware SPI.
     *
     * @param ss SPI slave select pin.
     * @param theSPI SPIClass instance (default is &SPI).
     */
    CryptnoxWallet(uint8_t ss, SPIClass *theSPI = &SPI)
        : driver(ss, theSPI) {}

    /**
     * @brief Construct a CryptnoxWallet over software SPI.
     *
     * @param clk Clock pin.
     * @param miso MISO pin.
     * @param mosi MOSI pin.
     * @param ss SPI slave select pin.
     */
    CryptnoxWallet(uint8_t clk, uint8_t miso, uint8_t mosi, uint8_t ss)
        : driver(clk, miso, mosi, ss) {}

    /**
     * @brief Construct a CryptnoxWallet over UART.
     *
     * @param reset Reset pin for PN532 (use -1 if unused).
     * @param theSer HardwareSerial instance.
     */
    CryptnoxWallet(uint8_t reset, HardwareSerial *theSer)
        : driver(reset, theSer) {}

    /**
     * @brief Initialize the PN532 module via the underlying driver.
     *
     * Performs SAM configuration and checks firmware version.
     *
     * @return true if the module was successfully initialized, false otherwise.
     */
    bool begin() {
        return driver.begin();
    }

    /**
     * @brief Detect and process an NFC card for Cryptnox wallet operations.
     *
     * If an ISO-DEP card is detected, SELECT APDU is sent and certificate is retrieved.
     * If only a passive card is detected, the UID is printed.
     *
     * @return true if a card was successfully processed, false otherwise.
     */
    bool processCard();

    /**
     * @brief Send the SELECT APDU to select the wallet application.
     *
     * @return true if the APDU exchange succeeded, false otherwise.
     */
    bool selectApdu();

    /**
     * @brief Send the GET CARD CERTIFICATE APDU.
     *
     * Generates RANDOM_BYTES random bytes for challenge and sends the APDU.
     *
     * @return true if the APDU exchange succeeded, false otherwise.
     */
    bool getCardCertificate();

    /**
     * @brief Read the UID of a detected card.
     *
     * @param uidBuffer Pointer to buffer to store the UID.
     * @param uidLength Reference to variable to store UID length.
     * @return true if the UID was read successfully, false otherwise.
     */
    bool readUID(uint8_t* uidBuffer, uint8_t &uidLength);

    /**
    * @brief Print detailed firmware information of the PN532 module.
    *
    * Retrieves the firmware version, parses IC type, major/minor versions,
    * and supported features, then prints all details to the Serial console.
    *
    * @return true if the PN532 module was detected and information printed, false otherwise.
    */
    bool printPN532FirmwareVersion();

private:
    PN532Base driver; /**< Internal driver for low-level PN532 operations */
};

#endif // CRYPTNOXWALLET_H
