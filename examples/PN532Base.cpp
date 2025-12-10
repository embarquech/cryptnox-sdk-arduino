#include "PN532Base.h"
#include <Arduino.h>

/**
 * @brief Initialize the PN532 module and configure it for normal operation.
 *
 * Calls the base Adafruit_PN532 `begin()`, reads the firmware version, 
 * prints a detailed status message, and performs SAM configuration.
 *
 * @return true if the PN532 module was successfully initialized and detected, false otherwise.
 */
bool PN532Base::begin(void) {
  return Adafruit_PN532::begin();
}

/**
 * @brief Read the UID of a detected NFC card.
 *
 * @param uidBuffer Pointer to buffer to store the UID.
 * @param uidLength Reference to variable to store the UID length.
 * @return true if a card was detected and UID read successfully, false otherwise.
 */
bool PN532Base::readUID(uint8_t* uidBuffer, uint8_t &uidLength) {
    return readPassiveTargetID(PN532_MIFARE_ISO14443A, uidBuffer, &uidLength);
}

/**
 * @brief Retrieve the firmware version of the PN532 module.
 *
 * The version is returned as a 32-bit value:
 * Bits 31:24 = IC type
 * Bits 23:16 = Major firmware version
 * Bits 15:8  = Minor firmware version
 * Bits 7:0   = Feature flags
 *
 * @param version Reference to variable to store the firmware version.
 * @return true if the firmware version was successfully retrieved, false otherwise.
 */
bool PN532Base::getFirmwareVersion(uint32_t &version) {
    version = Adafruit_PN532::getFirmwareVersion();
    return (version != 0);
}

/**
 * @brief Print detailed firmware information of the PN532 module.
 *
 * Retrieves the firmware version from the PN532 via the underlying driver,
 * parses the IC type, major and minor firmware versions, and supported features,
 * then prints all this information to the Serial console. Also performs SAM configuration.
 *
 * @return true if the PN532 module was detected and firmware information printed, false otherwise.
 */
bool PN532Base::printFirmwareVersion(void)
{
    uint32_t versionData;
    bool result = false;

    if (getFirmwareVersion(versionData) != false) {
        uint8_t ic       = (versionData >> 24U) & 0xFFU;
        uint8_t verMajor = (versionData >> 16U) & 0xFFU;
        uint8_t verMinor = (versionData >>  8U) & 0xFFU;
        uint8_t flags    =  versionData        & 0xFFU;
        bool first       = true;

        Serial.println(F("PN532 detected"));
        Serial.print(F(" ├─ Raw firmware: 0x"));
        Serial.println(versionData, HEX);

        Serial.print(F(" ├─ IC Chip: "));
        if (ic == 0x32U)
        {
            Serial.println(F("PN532"));
        }
        else
        {
            Serial.println(F("Unknown"));
        }

        Serial.print(F(" ├─ Firmware: "));
        Serial.print(verMajor);
        Serial.print(F("."));
        Serial.println(verMinor);

        Serial.print(F(" └─ Features: "));
        if ((flags & 0x01U) != 0U) {
            Serial.print(F("MIFARE"));
            first = false;
        }
        if ((flags & 0x02U) != 0U) {
            if (!first)
            {
                Serial.print(F(" + "));
            }
            Serial.print(F("ISO-DEP"));
            first = false;
        }
        if ((flags & 0x04U) != 0U) {
            if (!first)
            {
                Serial.print(F(" + "));
            }
            Serial.print(F("FeliCa"));
            first = false;
        }
        if (first) {
            Serial.print(F("Unknown"));
        }

        Serial.print(F(" (0x"));
        Serial.print(flags, HEX);
        Serial.println(F(")"));

        SAMConfig(); /* Configure the PN532 for normal operation */
        result = true;
    }
    else {
        Serial.println(F("PN532 not found!"));
        result = false;
    }

    return result;
}

/**
 * @brief Send an APDU command to an ISO14443-4 card and read the response.
 *
 * @param apdu Pointer to APDU command buffer.
 * @param apduLength Length of the APDU command in bytes.
 * @param response Pointer to buffer to store the card response.
 * @param responseLength Reference to variable for response length.
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool PN532Base::sendAPDU(const uint8_t* apdu, uint8_t apduLength,
                         uint8_t* response, uint8_t &responseLength) {
    bool success = inDataExchange(
        (uint8_t*)apdu,
        apduLength,
        response,
        &responseLength
    );

    if (success == false) {
        Serial.println(F("APDU exchange failed!"));
        return false;
    }

    Serial.print(F("APDU response ("));
    Serial.print(responseLength);
    Serial.println(F(" bytes):"));

    for (uint8_t i = 0; i < responseLength; i++) {
        Serial.print("0x");
        if (response[i] < 16) {
            Serial.print("0");
        }
        Serial.print(response[i], HEX);
        Serial.print(" ");

        /* Wrap line every 16 bytes */
        if ((i + 1) % 16 == 0 && (i + 1) != responseLength) Serial.println();
    }
    Serial.println();

    return true;
}
