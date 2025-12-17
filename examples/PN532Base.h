#ifndef PN532BASE_H
#define PN532BASE_H

#include <Adafruit_PN532.h>

/**
 * @class PN532Base
 * @brief Wrapper around Adafruit_PN532 providing extended utility functions for NFC card operations.
 *
 * This class inherits all constructors from Adafruit_PN532, allowing initialization
 * via I2C, SPI, Software SPI, or UART. It adds convenience methods for reading UID,
 * retrieving firmware version, and sending APDU commands to ISO14443-4 cards.
 */
class PN532Base : public Adafruit_PN532 {
public:
    /**
     * @brief Inherit all constructors from Adafruit_PN532.
     *
     * Allows initialization using any supported bus with the same parameters
     * as the original Adafruit_PN532 constructors.
     */
    using Adafruit_PN532::Adafruit_PN532;

    /**
     * @brief Initialize the PN532 module and configure it for normal operation.
     *
     * Starts the internal PN532 hardware, reads the firmware version,
     * and performs SAM configuration. Prints debug messages to Serial.
     *
     * @return true if the PN532 module was successfully initialized, false otherwise.
     */
    bool begin(void);

    /**
     * @brief Read the UID of a detected NFC card.
     *
     * @param uidBuffer Pointer to a buffer where the UID will be stored.
     * @param uidLength Reference to a variable that will hold the length of the UID.
     * @return true if a card was detected and UID read successfully, false otherwise.
     */
    bool readUID(uint8_t* uidBuffer, uint8_t &uidLength);

    /**
    * @brief Retrieve the firmware version of the PN532 module.
    *
    * The firmware version is returned as a 32-bit value where:
    * - Bits 31:24 = IC type
    * - Bits 23:16 = Major firmware version
    * - Bits 15:8  = Minor firmware version
    * - Bits 7:0   = Supported feature flags
    *
    * @param version Reference to a uint32_t variable to store the firmware version.
    * @return true if the firmware version was successfully retrieved, false otherwise.
    */
    bool getFirmwareVersion(uint32_t &version);

    /**
    * @brief Print detailed firmware information of the PN532 module.
    *
    * Retrieves the firmware version, parses IC type, major/minor versions, 
    * supported features, and prints all details to the Serial console.
    * Also configures the PN532 using SAMConfig().
    *
    * @return true if the PN532 module was detected and information printed, false otherwise.
    */
    bool printFirmwareVersion();

    /**
     * @brief Send an APDU command to an ISO14443-4 (Type 4) NFC card.
     *
     * This method exchanges raw APDU bytes with a card and retrieves the response.
     *
     * @param apdu Pointer to the APDU command buffer to send.
     * @param apduLength Length of the APDU command buffer in bytes.
     * @param response Pointer to a buffer where the card's response will be stored.
     * @param responseLength Reference to a variable that will hold the length of the response.
     * @return true if the APDU exchange was successful, false otherwise.
     */
    bool sendAPDU(const uint8_t* apdu, uint8_t apduLength,
                  uint8_t* response, uint8_t &responseLength);

    /**
    * @brief Reset the PN532 reader to allow card detection again.
    *
    * Internally calls SAMConfig() to reinitialize the reader.
    */
    void resetReader(void);
};

#endif // PN532BASE_H
