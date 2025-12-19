#ifndef PN532ADAPTER_H
#define PN532ADAPTER_H

#include <Arduino.h>
#include <Adafruit_PN532.h>
#include "NFCDriver.h"

/**
 * @brief Enum representing the supported communication interfaces for the PN532 NFC module.
 *
 * This allows the PN532Adapter to work over multiple physical interfaces:
 * hardware SPI, software SPI, I2C, or UART. The interface is set when constructing
 * the adapter and is used internally to configure the Adafruit_PN532 driver accordingly.
 */
enum class PN532Interface {
    SPI_HARDWARE, /* Use hardware SPI. */
    SPI_SOFTWARE, /* Use software SPI (bit-banging). */
    I2C,          /* Use I2C interface. */
    UART          /* Use UART interface. */
};

/**
 * @brief Adapter class wrapping the Adafruit_PN532 library.
 *
 * PN532Adapter provides a unified interface conforming to NFCDriver,
 * abstracting the underlying hardware interface. This allows higher-level
 * code (like CryptnoxWallet) to operate independently of whether the
 * PN532 module is connected via SPI, I2C, or UART.
 *
 * The adapter handles initialization, UID reading, APDU communication,
 * passive target detection, firmware info retrieval, and reader reset.
 */
class PN532Adapter : public NFCDriver {
public:
    /**
     * @brief Constructs a PN532Adapter using hardware SPI.
     *
     * @param ssPin The SPI slave select (SS) pin connected to the PN532.
     * @param theSPI Pointer to SPIClass instance to use (default is &SPI).
     *
     * @note This constructor configures the Adafruit_PN532 driver for hardware SPI.
     */
    PN532Adapter(uint8_t ssPin, SPIClass *theSPI = &SPI);

    /**
     * @brief Constructs a PN532Adapter using software SPI (bit-banged).
     *
     * @param clk Clock pin.
     * @param miso MISO pin.
     * @param mosi MOSI pin.
     * @param ss SPI slave select pin.
     *
     * @note Software SPI allows usage of arbitrary pins but is slower than hardware SPI.
     */
    PN532Adapter(uint8_t clk, uint8_t miso, uint8_t mosi, uint8_t ss);

    /**
     * @brief Constructs a PN532Adapter using the I2C interface.
     *
     * @param irqPin The IRQ pin (optional for some configurations).
     * @param resetPin The reset pin of the PN532 module.
     * @param wire Pointer to TwoWire instance to use (default is &Wire).
     */
    PN532Adapter(uint8_t irqPin, uint8_t resetPin, TwoWire *wire = &Wire);

    /**
     * @brief Constructs a PN532Adapter using UART.
     *
     * @param resetPin The reset pin of the PN532 module.
     * @param serial Pointer to HardwareSerial instance to use for UART.
     */
    PN532Adapter(uint8_t resetPin, HardwareSerial *serial);

    /**
     * @brief Destructor.
     *
     * Cleans up the internally allocated Adafruit_PN532 instance.
     */
    ~PN532Adapter();

    /** @name NFCDriver Interface Overrides */
    ///@{
    
    /**
     * @brief Initialize the PN532 module.
     *
     * Calls Adafruit_PN532::begin() and checks that the firmware is accessible.
     *
     * @return true if initialization was successful and the PN532 firmware is detected.
     * @return false if the PN532 could not be initialized.
     */
    bool begin() override;

    /**
     * @brief Read the UID of the currently detected NFC card.
     *
     * @param uidBuffer Pointer to buffer where the UID will be stored.
     * @param uidLength Reference to a variable to receive the UID length.
     * @return true if a card was detected and the UID read successfully.
     * @return false otherwise.
     */
    bool readUID(uint8_t* uidBuffer, uint8_t &uidLength) override;

    /**
     * @brief Send an APDU command to the NFC card and receive its response.
     *
     * @param apdu Pointer to APDU command buffer.
     * @param apduLength Length of APDU command in bytes.
     * @param response Pointer to buffer where the card's response will be stored.
     * @param responseLength Reference to variable to receive length of the response.
     * @return true if the APDU command was successfully sent and a response received.
     * @return false if the exchange failed.
     */
    bool sendAPDU(const uint8_t* apdu, uint16_t apduLength,
                  uint8_t* response, uint8_t &responseLength) override;

    /**
     * @brief Checks for presence of a passive NFC target.
     *
     * @return true if a passive target (card) is present.
     * @return false otherwise.
     */
    bool inListPassiveTarget() override;

    /**
     * @brief Reset the PN532 module and reconfigure the reader.
     */
    void resetReader() override;

    /**
     * @brief Prints the PN532 firmware version and chip information to Serial.
     *
     * @return true if the firmware information was successfully retrieved.
     * @return false if the PN532 was not detected.
     */
    bool printFirmwareVersion() override;

    ///@}

private:
    PN532Interface interface; ///< The active interface type currently used.
    Adafruit_PN532* nfc;      ///< Pointer to the underlying Adafruit_PN532 instance.
};

#endif // PN532ADAPTER_H
