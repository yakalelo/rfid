#ifndef RFID_MYKNOWNKEYS_h
#define RFID_MYKNOWNKEYS_h

#include <MFRC522.h>

// Known keys, see: https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys

byte knownKeys[][MFRC522::MF_KEY_SIZE] =  {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // FF FF FF FF FF FF = factory default
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}, // A0 A1 A2 A3 A4 A5
    {0x41, 0x42, 0x43, 0x44, 0x45, 0x46}
};
#endif
