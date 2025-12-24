#include "PN532Adapter.h"

#define PN532BASE_READUID_TIMEOUT_MS    (3000U)

/**
 * @brief Construct a PN532Adapter using hardware SPI.
 *
 * @param ssPin SPI slave select pin connected to the PN532 module.
 * @param theSPI Pointer to SPIClass instance (default: &SPI).
 */
PN532Adapter::PN532Adapter(uint8_t ssPin, SPIClass *theSPI)
    : interface(PN532Interface::SPI_HARDWARE)
{
    nfc = new Adafruit_PN532(ssPin, theSPI);
}

/**
 * @brief Construct a PN532Adapter using software SPI (bit-banged).
 *
 * @param clk Clock pin.
 * @param miso MISO pin.
 * @param mosi MOSI pin.
 * @param ss SPI slave select pin.
 */
PN532Adapter::PN532Adapter(uint8_t clk, uint8_t miso, uint8_t mosi, uint8_t ss)
    : interface(PN532Interface::SPI_SOFTWARE) {
    nfc = new Adafruit_PN532(clk, miso, mosi, ss);
}

/**
 * @brief Construct a PN532Adapter using I2C.
 *
 * @param irqPin IRQ pin (if applicable).
 * @param resetPin Reset pin of PN532.
 * @param wire Pointer to TwoWire instance (default: &Wire).
 */
PN532Adapter::PN532Adapter(uint8_t irqPin, uint8_t resetPin, TwoWire *wire)
    : interface(PN532Interface::I2C) {
    nfc = new Adafruit_PN532(irqPin, resetPin, wire);
}

/**
 * @brief Construct a PN532Adapter using UART.
 *
 * @param resetPin Reset pin of PN532.
 * @param serial Pointer to HardwareSerial instance to use.
 */
PN532Adapter::PN532Adapter(uint8_t resetPin, HardwareSerial *serial)
    : interface(PN532Interface::UART) {
    nfc = new Adafruit_PN532(resetPin, serial);
}

/**
 * @brief Destructor. Cleans up the dynamically allocated Adafruit_PN532 instance.
 */
PN532Adapter::~PN532Adapter() {
    if (nfc) {
        delete nfc;
        nfc = nullptr;
    }
}

/**
 * @brief Initialize the PN532 module.
 *
 * Calls Adafruit_PN532::begin() and checks firmware.
 *
 * @return true if the module is detected and initialized.
 * @return false otherwise.
 */
bool PN532Adapter::begin() {
    nfc->begin();
    return nfc->getFirmwareVersion() != 0;
}

/**
 * @brief Read the UID of the currently detected NFC card.
 *
 * @param uidBuffer Buffer to store the UID.
 * @param uidLength Variable to store the UID length.
 * @return true if a card was detected and UID read successfully.
 * @return false otherwise.
 */
bool PN532Adapter::readUID(uint8_t* uidBuffer, uint8_t &uidLength) {
    return nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uidBuffer, &uidLength, PN532BASE_READUID_TIMEOUT_MS);
}

/**
 * @brief Send an APDU command to a card and receive its response.
 *
 * @param apdu Pointer to APDU command buffer.
 * @param apduLength Length of APDU command in bytes.
 * @param response Buffer to receive the card's response.
 * @param responseLength Variable to store the length of the response.
 * @return true if APDU exchange succeeded.
 * @return false otherwise.
 */
bool PN532Adapter::sendAPDU(const uint8_t* apdu, uint16_t apduLength,
                            uint8_t* response, uint8_t &responseLength) {
    bool success = nfc->inDataExchange(const_cast<uint8_t*>(apdu), apduLength, response, &responseLength);

    if (!success) {
        Serial.println(F("APDU exchange failed!"));
        return false;
    }

    Serial.print(F("APDU response ("));
    Serial.print(responseLength);
    Serial.println(F(" bytes):"));

    for (uint8_t i = 0; i < responseLength; i++) {
        Serial.print(F("0x"));
        if (response[i] < 16) Serial.print(F("0"));
        Serial.print(response[i], HEX);
        Serial.print(F(" "));
        if ((i + 1) % 16 == 0 && (i + 1) != responseLength) Serial.println();
    }
    Serial.println();

    return true;
}

/**
 * @brief Check if a passive target (card) is present.
 *
 * @return true if a card is detected.
 * @return false otherwise.
 */
bool PN532Adapter::inListPassiveTarget() {
    return nfc->inListPassiveTarget();
}

/**
 * @brief Reset the PN532 reader and configure it.
 */
void PN532Adapter::resetReader() {
    nfc->SAMConfig();
}

/**
 * @brief Print firmware and chip information to Serial.
 *
 * @return true if information was successfully retrieved.
 * @return false if the PN532 module was not detected.
 */
bool PN532Adapter::printFirmwareVersion() {

    uint32_t versionData = nfc->getFirmwareVersion();
    bool result = false;

    if (versionData != false) {
        uint8_t ic       = (versionData >> 24U) & 0xFFU;
        uint8_t verMajor = (versionData >> 16U) & 0xFFU;
        uint8_t verMinor = (versionData >>  8U) & 0xFFU;
        uint8_t flags    =  versionData        & 0xFFU;
        bool first       = true;

        Serial.println(F("PN532 information"));
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

        nfc->SAMConfig(); /* Configure the PN532 for normal operation */
        result = true;
    }
    else {
        Serial.println(F("PN532 not found!"));
        result = false;
    }

    return result;
}
