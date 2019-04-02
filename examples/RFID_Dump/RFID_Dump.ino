/* -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 */

#include <SPI.h>
#include <MFRC522.h>
#include <EEPROM.h>
#include "RFID_Utils.h"
#include "RFID_MyKnownKeys.h"

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above
MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

bool verbose = false;

#define SECTOR_NUMBER    16
#define BLOCK_NUMBER     64
#define BLOCK_PER_SECTOR 4
#define BLOCK_SIZE       16
#define BLOCK_SIZE_CRC   18
#define DUMP_SIZE        1024

byte buffer[BLOCK_SIZE_CRC];
byte sector;
byte block;
MFRC522::StatusCode status;
MFRC522::MIFARE_Key key;
unsigned int foundKeysA;   // 0000 0000 0000 0001  <-  found key A of sector 0
unsigned int foundKeysB;   // 1000 0000 0011 0000  <-  found key B of sectors 4, 5 and 15
MFRC522::MIFARE_Key aFoundKeysA[SECTOR_NUMBER];
MFRC522::MIFARE_Key aFoundKeysB[SECTOR_NUMBER];
bool aReadBlocks[BLOCK_NUMBER];
////////////////////////struct_accessBits accessBits/* {false, false, false}*/;
struct_accessBits accessBits;

byte currentDump[BLOCK_NUMBER * BLOCK_SIZE];
/*                   +-----------------------------------------------+
 *                   | Byte Number within a Block                    |
 *  +--------+-------+-----------------------------------------------+-------------------+
 *  | Sector | Block | 0| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15| Description       |
 *  +--------+-------+-----------------+-----------+-----------------+-------------------+
 *  |   15   |   3   |      Key A      |Access Bits|      Key B      | Sector Trailer 15 |
 *  |        |   2   |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | Data              |
 *  |        |   1   |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | Data              |
 *  |        |   0   |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | Data              |
 *  +--------+-------+-----------------------------------------------+-------------------+
 * 
 * */

#define AC_ST_000 "never | key A | key A   | never | key A | key A | Key B may be read                          |"
#define AC_ST_010 "never | never | key A   | never | key A | never | Key B may be read                          |"
#define AC_ST_100 "never | key B | key A|B | never | never | key B |                                            |"
#define AC_ST_110 "never | never | key A|B | never | never | never |                                            |"
#define AC_ST_001 "never | key A | key A   | key A | key A | key A | Key B may be read, transport configuration |"
#define AC_ST_011 "never | key B | key A|B | key B | never | key B |                                            |"
#define AC_ST_101 "never | never | key A|B | key B | never | never |                                            |"
#define AC_ST_111 "never | never | key A|B | never | never | never |                                            |"

#define AC_DB_000 "key A|B  | key A|B  | key A|B     | key A|B     | transport configuration                    |"
#define AC_DB_010 "key A|B  | never    | never       | never       | read/write block                           |"
#define AC_DB_100 "key A|B  | key B    | never       | never       | read/write block                           |"
#define AC_DB_110 "key A|B  | key B    | key B       | key A|B     | value block                                |"
#define AC_DB_001 "key A|B  | never    | never       | key A|B     | value block                                |"
#define AC_DB_011 "key B    | key B    | never       | never       | read/write block                           |"
#define AC_DB_101 "key B    | never    | never       | never       | read/write block                           |"
#define AC_DB_111 "never    | never    | never       | never       | read/write block                           |"


/*
 * 
 */
void getAccessBitsFromDump(byte p_block, byte p_dump[], struct_accessBits *p_accessBits) {
  byte sector = p_block / BLOCK_PER_SECTOR;
  byte block_of_sector_trailer = sector * BLOCK_PER_SECTOR + 3;
  byte byte7_of_sector_trailer = p_dump[block_of_sector_trailer * BLOCK_SIZE + 7];
  byte byte8_of_sector_trailer = p_dump[block_of_sector_trailer * BLOCK_SIZE + 8];

  getAccessBits(p_block, byte7_of_sector_trailer, byte8_of_sector_trailer, p_accessBits);
  
  return;
}


/*
 * 
 */
void displayCurrentDump() {
  Serial.println(F("+------+-----+-------------------------------------------------+-----------+-------------------------------------------------+--------------------------------------------+"));
  Serial.println(F("|Sector|Block| Sector trailer / Data blocks / Value blocks     |Access bits| Access condition for                            | Remark / Application                       |"));
  
  byte block = BLOCK_NUMBER;
  while (block > 0) {
    block--;
    byte sector = block / BLOCK_PER_SECTOR;
    byte block_in_sector = block % BLOCK_PER_SECTOR;
    if (block_in_sector == 3) {
      Serial.println(F("+------+-----+-------------------------------------------------+-----------+-------------------------------------------------+--------------------------------------------+"));
      Serial.print(F("|      |     |                                                 |           |     KEY A     |   Access bits   |     KEY B     |                                            | KEY A ="));
      dump_byte_array4(&currentDump[block * BLOCK_SIZE], MFRC522::MF_KEY_SIZE);
      Serial.println();
      Serial.print(F("|      |     |                  v           v                  | C1 C2 C3  | read  | write | read    | write | read  | write |                                            | KEY B ="));
      dump_byte_array4(&currentDump[block * BLOCK_SIZE + MFRC522::MF_KEY_SIZE + 4], MFRC522::MF_KEY_SIZE);
      Serial.println();
      Serial.print(F("|  ")); Serial.print(sector < 10 ? " " : ""); Serial.print(sector);
    }
    else if (block_in_sector == 2) {
      Serial.println(F("+ - - -+ - - + - - - - - - - - - - - - - - - - - - - - - - - - + - - - - - + - - - - - - - - - - - - - - - - - - - - - - - - + - - - - - - - - - - - - - - - - - - - - - -+"));
//      Serial.println(F("|      |     |                                                 |           | read     | write    | increment   | decrement,  |                                            |"));
//      Serial.println(F("|      |     |                                                 |           |          |          |             | transfert,  |                                            |"));
//      Serial.println(F("|      |     |                                                 |           |          |          |             | restore     |                                            |"));
      Serial.print(F("|    "));
    }
    else {
      Serial.print(F("|    "));
    }
    Serial.print(F("  | ")); Serial.print(block < 10 ? " " : ""); Serial.print(block); Serial.print(F("  |"));
    for (byte i = 0; i < BLOCK_SIZE; i++) {
      if (aReadBlocks[block]) {
        Serial.print(currentDump[block * BLOCK_SIZE + i] < 0x10 ? " 0" : " ");
        Serial.print(currentDump[block * BLOCK_SIZE + i], HEX);
      }
      else {
        Serial.print(F(" ??"));
      }
    }
    getAccessBitsFromDump(block, currentDump, &accessBits);
    Serial.print(F(" |  ")); Serial.print(accessBits.c1); Serial.print(F("  ")); Serial.print(accessBits.c2); Serial.print(F("  ")); Serial.print(accessBits.c3); Serial.print(F("  | "));
    if (block_in_sector == 3) {
      if (!accessBits.c1 && !accessBits.c2 && !accessBits.c3) Serial.print(F(AC_ST_000));
      if (!accessBits.c1 &&  accessBits.c2 && !accessBits.c3) Serial.print(F(AC_ST_010));
      if ( accessBits.c1 && !accessBits.c2 && !accessBits.c3) Serial.print(F(AC_ST_100));
      if ( accessBits.c1 &&  accessBits.c2 && !accessBits.c3) Serial.print(F(AC_ST_110));
      if (!accessBits.c1 && !accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_ST_001));
      if (!accessBits.c1 &&  accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_ST_011));
      if ( accessBits.c1 && !accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_ST_101));
      if ( accessBits.c1 &&  accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_ST_111));
    }
    else { // block_in_sector == 2 || block_in_sector == 1 || block_in_sector == 0
      if (!accessBits.c1 && !accessBits.c2 && !accessBits.c3) Serial.print(F(AC_DB_000));
      if (!accessBits.c1 &&  accessBits.c2 && !accessBits.c3) Serial.print(F(AC_DB_010));
      if ( accessBits.c1 && !accessBits.c2 && !accessBits.c3) Serial.print(F(AC_DB_100));
      if ( accessBits.c1 &&  accessBits.c2 && !accessBits.c3) Serial.print(F(AC_DB_110));
      if (!accessBits.c1 && !accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_DB_001));
      if (!accessBits.c1 &&  accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_DB_011));
      if ( accessBits.c1 && !accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_DB_101));
      if ( accessBits.c1 &&  accessBits.c2 &&  accessBits.c3) Serial.print(F(AC_DB_111));
    }
    dump_byte_array4(&currentDump[block * BLOCK_SIZE], BLOCK_SIZE);
    Serial.println();
    if (block_in_sector == 0) {
      Serial.println(F("|      |     |                                                 |           | read     | write    | increment   | decrement,  |                                            |"));
      Serial.println(F("|      |     |                                                 |           |          |          |             | transfert,  |                                            |"));
      Serial.println(F("|      |     |                                                 |           |          |          |             | restore     |                                            |"));
//      Serial.print(F("|    "));
    }
  }
  Serial.println(F("+------+-----+-------------------------------------------------+-----------+-------------------------------------------------+--------------------------------------------+"));
} // End display_current_dump()



/*
 * Returns true if all sectors authenticated with default keys
 * [Key: FFFFFFFFFFFF] -> [xxxxxxxx.......x]
 * [Key: A0A1A2A3A4A5] -> [xxxxxxxx///////x]
 * [Key: AABBCCDDEEFF] -> [xxxxxxxxxxxxxxxx]
 */
bool tryToAuthenticateToAllSectorsWithDefaultKeys() {
  bool areAllKeysFound = false;
  
  foundKeysA = 0; // 0b0000000000000000
  foundKeysB = 0; // 0b0000000000000000
  
  Serial.println(F("Try to authenticate to all sectors with default keys..."));
  Serial.println(F("Symbols: '.' no key found, '/' A key found, '\' B key found, 'x' both keys found"));
  int nbKnownKeys = sizeof(knownKeys) / MFRC522::MF_KEY_SIZE;
  for (byte k = 0; (k < nbKnownKeys) && ((foundKeysA < 0b1111111111111111) || (foundKeysB < 0b1111111111111111)); k++) {
    for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
      key.keyByte[i] = knownKeys[k][i];
    }
    Serial.print(F("[Key: "));
    dump_byte_array2(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.print(F("] -> ["));
    for (sector = 0; sector < SECTOR_NUMBER; sector++) {
      block = (sector << 2) + 3;
      if ( ! bitRead(foundKeysA, sector)) {
        bool foundKeyA = tryAuthenticateWithKeyBlockCommand(2, &key, block, MFRC522::PICC_CMD_MF_AUTH_KEY_A, mfrc522, verbose);
        if (foundKeyA) {
          bitSet(foundKeysA, sector);
          for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
            aFoundKeysA[sector].keyByte[i] = key.keyByte[i];
            // sector 0 --> block 3 --> byte 48
            // sector 1 --> block 7 --> byte 112
            currentDump[sector * BLOCK_PER_SECTOR * BLOCK_SIZE + 3 * BLOCK_SIZE + i] = key.keyByte[i];
          }
        }
      }
      if ( ! bitRead(foundKeysB, sector)) {
        bool foundKeyB = tryAuthenticateWithKeyBlockCommand(2, &key, block, MFRC522::PICC_CMD_MF_AUTH_KEY_B, mfrc522, verbose);
        if (foundKeyB) {
          bitSet(foundKeysB, sector);
          for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
            aFoundKeysB[sector].keyByte[i] = key.keyByte[i];
            // sector 0 --> block 3 --> byte 58
            // sector 1 --> block 7 --> byte 122
            currentDump[sector * BLOCK_PER_SECTOR * BLOCK_SIZE + 3 * BLOCK_SIZE + 10 + i] = key.keyByte[i];
          }
        }
      }
      if (bitRead(foundKeysA, sector) && bitRead(foundKeysB, sector)) {
        Serial.print(F("x"));
        aReadBlocks[block] = true;
      }
      else if (bitRead(foundKeysA, sector)) {
        Serial.print(F("/"));
      }
      else if (bitRead(foundKeysB, sector)) {
        Serial.print(F("\\"));
      }
      else {
        Serial.print(F("."));
      }
    }
    Serial.println(F("]"));
  }
  if (foundKeysA == 0b1111111111111111 && foundKeysB == 0b1111111111111111) {
    areAllKeysFound = true;
  }
  
  return areAllKeysFound;
}



/*
 * Returns true if all sectors authenticated with default keys
 * [Key: FFFFFFFFFFFF] -> [.]
 * [Key: A0A1A2A3A4A5] -> [/]
 * [Key: AABBCCDDEEFF] -> [x]
 */
bool tryToAuthenticateToOneSectorWithDefaultKeys(byte p_sector) {
  bool areAllKeysFound = false;
  
  bool foundKeyA;
  bool foundKeyB;
  
  Serial.print(F("Try to authenticate to sector ")); Serial.print(p_sector); Serial.println(F(" with default keys..."));
  Serial.println(F("Symbols: '.' no key found, '/' A key found, '\' B key found, 'x' both keys found"));
  int nbKnownKeys = sizeof(knownKeys) / MFRC522::MF_KEY_SIZE;
  for (byte k = 0; (k < nbKnownKeys) && ( !foundKeyA || !foundKeyB); k++) {
    Serial.print(F("[Key: ")); dump_byte_array2(key.keyByte, MFRC522::MF_KEY_SIZE); Serial.print(F("] -> ["));
    block = (sector << 2) + 3;
    if (!foundKeyA) {
      foundKeyA = tryAuthenticateWithKeyBlockCommand(2, knownKeys[k], block, MFRC522::PICC_CMD_MF_AUTH_KEY_A, mfrc522, verbose);
    }
    if (!foundKeyB) {
      foundKeyB = tryAuthenticateWithKeyBlockCommand(2, knownKeys[k], block, MFRC522::PICC_CMD_MF_AUTH_KEY_B, mfrc522, verbose);
    }
    if (foundKeyA && foundKeyB) {
      Serial.print(F("x"));
      aReadBlocks[block] = true;
    }
    else if (foundKeyA) {
      Serial.print(F("/"));
    }
    else if (foundKeyB) {
      Serial.print(F("\\"));
    }
    else {
      Serial.print(F("."));
    }
  }
  Serial.println(F("]"));
  if (foundKeyA && foundKeyB) {
    areAllKeysFound = true;
  }
  
  return areAllKeysFound;
}


/*
 * Sector 00 - Found   Key A: FFFFFFFFFFFF Found   Key B: FFFFFFFFFFFF
 * Sector 01 - Found   Key A: FFFFFFFFFFFF Found   Key B: FFFFFFFFFFFF
 * Sector 08 - Found   Key A: A0A1A2A3A4A5 Found   Key B: A0A1A2A3A4A5
 */
void dumpKnownKeys() {
  for (sector = 0; sector < SECTOR_NUMBER; sector++) {
    Serial.print(F("Sector "));
    Serial.print(sector < 10 ? "0" : "");
    Serial.print(sector);
    Serial.print(F(" - "));
    if (bitRead(foundKeysA, sector)) {
      Serial.print(F("Found   Key A: "));
      dump_byte_array2(aFoundKeysA[sector].keyByte, MFRC522::MF_KEY_SIZE);
    }
    else {
      Serial.print(F("Unknown Key A:              "));
    }
    if (bitRead(foundKeysB, sector)) {
      Serial.print(F(" Found   Key B: "));
      dump_byte_array2(aFoundKeysB[sector].keyByte, MFRC522::MF_KEY_SIZE);
    }
    else {
      Serial.print(F(" Unknown Key B:              "));
    }
    Serial.println();
  }
}




/*
 * 
 */
void readAccessBitsOfAllSectors(MFRC522 p_mfrc522) {
  Serial.println(F("readAccessBitsOfAllSectors"));
  for (byte sector = 0; sector < SECTOR_NUMBER; sector++) {
    Serial.print(sector);
    Serial.print(F(" "));
    byte block = (sector << 2) + 3;
    byte bufferSize = sizeof(buffer);
    readBlock(&aFoundKeysA[sector], block, MFRC522::PICC_CMD_MF_AUTH_KEY_A, buffer, &bufferSize, p_mfrc522, verbose);
    for (byte i = 6; i < 10; i++) {
      currentDump[block * BLOCK_SIZE + i] = buffer[i];
    }
  }
  Serial.println();
}


/*
 * 
 */
bool canDataBlockBeReadWithKeyA(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);

  return canDataBlockBeReadWithKeyA(&accessBits);
}
/*
 * 
 */
bool canDataBlockBeReadWithKeyB(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canDataBlockBeReadWithKeyB(&accessBits);
}
/*
 * 
 */
bool canDataBlockBeWrittenWithKeyA(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canDataBlockBeWrittenWithKeyA(&accessBits);
}
/*
 * 
 */
bool canDataBlockBeWrittenWithKeyB(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canDataBlockBeWrittenWithKeyB(&accessBits);
}
/*
 * 
 */
bool canKeyABeWrittenWithKeyA(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canKeyABeWrittenWithKeyA(&accessBits);
}
/*
 * 
 */
bool canKeyABeWrittenWithKeyB(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canKeyABeWrittenWithKeyB(&accessBits);
}
/*
 * 
 */
bool canAccessBitsBeWrittenWithKeyA(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canAccessBitsBeWrittenWithKeyA(&accessBits);
}
/*
 * 
 */
bool canAccessBitsBeWrittenWithKeyB(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canAccessBitsBeWrittenWithKeyB(&accessBits);
}
/*
 * 
 */
bool canKeyBBeWrittenWithKeyA(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canKeyBBeWrittenWithKeyA(&accessBits);
}
/*
 * 
 */
bool canKeyBBeWrittenWithKeyB(byte p_block) {
//  struct_accessBits accessBits;
  getAccessBitsFromDump(p_block, currentDump, &accessBits);
  
  return canKeyBBeWrittenWithKeyB(&accessBits);
}


/*
 * 
 */
void readAllDataBlocks(MFRC522 p_mfrc522) {
  Serial.println(F("readAllDataBlocks"));
  for (byte block = 0; block < BLOCK_NUMBER; block++) {
    byte sector = block / BLOCK_PER_SECTOR;
    byte block_in_sector = block % BLOCK_PER_SECTOR;
    if (block_in_sector != 3) {
      Serial.print(block);
      Serial.print(F(" "));
      byte bufferSize = sizeof(buffer);
      if (canDataBlockBeReadWithKeyA(block)) {
        aReadBlocks[block] = readBlock(&aFoundKeysA[sector], block, MFRC522::PICC_CMD_MF_AUTH_KEY_A, buffer, &bufferSize, p_mfrc522, verbose);
      }
      else if (canDataBlockBeReadWithKeyB(block)) {
        aReadBlocks[block] = readBlock(&aFoundKeysB[sector], block, MFRC522::PICC_CMD_MF_AUTH_KEY_B, buffer, &bufferSize, p_mfrc522, verbose);
      }
      else {
        aReadBlocks[block] = false;
      }
      for (byte i = 0; i < BLOCK_SIZE; i++) {
        currentDump[block * BLOCK_SIZE + i] = buffer[i];
      }
    }
    else {
      Serial.print(F("- "));
    }
  }
  Serial.println();
}


void saveDumpInEEPROM() {
  Serial.println(F("saveDumpInEEPROM"));
  Serial.print(F("EEPROM.length = "));
  Serial.print(EEPROM.length());

  for (int i = 0; i < DUMP_SIZE; i++) {
    if (i % BLOCK_SIZE == 0) {
      Serial.println();
      Serial.print((i / BLOCK_SIZE) < 10 ? " " : "");
      Serial.print(i / BLOCK_SIZE);
      Serial.print(F(" --> "));
    }
    Serial.print(currentDump[i] < 0x10 ? " 0" : " ");
    Serial.print(currentDump[i], HEX);
    EEPROM.write(i, currentDump[i]);
  }
  Serial.println();
   
  return;
}

void loadDumpFromEEPROM() {
  Serial.println(F("loadDumpFromEEPROM"));
  Serial.print(F("EEPROM.length = "));
  Serial.print(EEPROM.length());

  for (int i = 0; i < DUMP_SIZE; i++) {
    if (i % BLOCK_SIZE == 0) {
      Serial.println();
      Serial.print((i / BLOCK_SIZE) < 10 ? " " : "");
      Serial.print(i / BLOCK_SIZE);
      Serial.print(F(" <-- "));
    }
    currentDump[i] = EEPROM.read(i);
    Serial.print(currentDump[i] < 0x10 ? " 0" : " ");
    Serial.print(currentDump[i], HEX);
  }
  Serial.println();
   
  return;
}


/*  SSSSS  EEEEEEE TTTTTTT UU   UU PPPPPP  
 * SS      EE        TTT   UU   UU PP   PP 
 *  SSSSS  EEEEE     TTT   UU   UU PPPPPP  
 *      SS EE        TTT   UU   UU PP      
 *  SSSSS  EEEEEEE   TTT    UUUUU  PP      */
void setup() {
  Serial.begin(115200);       // Initialize serial communications with the PC
  while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();                // Init SPI bus
  mfrc522.PCD_Init();         // Init MFRC522 card
  
  Serial.println(); Serial.println(F("=========================================================")); Serial.println();
  Serial.println(F("Ready to Dump"));
  Serial.println(F("Insert new card..."));
}





/* LL       OOOOO   OOOOO  PPPPPP  
 * LL      OO   OO OO   OO PP   PP 
 * LL      OO   OO OO   OO PPPPPP  
 * LL      OO   OO OO   OO PP      
 * LLLLLLL  OOOO0   OOOO0  PP      */
void loop() {
  mfrc522.PCD_Init();         // Init MFRC522 card
  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }
  
  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  
  // Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Card UID:"));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

/*
  formatSector(knownKeys[0], knownKeys[0], 1, mfrc522, verbose);
  formatSector(knownKeys[0], knownKeys[0], 8, mfrc522, verbose);
  formatSector(knownKeys[0], knownKeys[0], 9, mfrc522, verbose);
  formatSector(knownKeys[1], knownKeys[2], 10, mfrc522, verbose);
  formatSector(knownKeys[1], knownKeys[2], 11, mfrc522, verbose);
  formatSector(knownKeys[1], knownKeys[2], 12, mfrc522, verbose);
*/


  
  bool areAllKeysFound = tryToAuthenticateToAllSectorsWithDefaultKeys();
  Serial.println();
  dumpKnownKeys();
  Serial.println();
  if (areAllKeysFound) {
    Serial.println(F("We have all sectors encrypted with the default keys..."));
  }
  Serial.println();



  readAccessBitsOfAllSectors(mfrc522);
  readAllDataBlocks(mfrc522);
  displayCurrentDump();
  //saveDumpInEEPROM();
  //loadDumpFromEEPROM();
  
  Serial.println(); Serial.println(F("=========================================================")); Serial.println();
  Serial.print(F("  5"));
  delay(500);
  Serial.print(F(" . "));
  delay(500);
  Serial.print(F("4"));
  delay(500);
  Serial.print(F(" . "));
  delay(500);
  Serial.print(F("3"));
  delay(500);
  Serial.print(F(" . "));
  delay(500);
  Serial.print(F("2"));
  delay(500);
  Serial.print(F(" . "));
  delay(500);
  Serial.print(F("1"));
  delay(500);
  Serial.print(F(" . "));
  delay(500);
  Serial.println(F("0"));
  Serial.println(F("Ready to Dump"));
  Serial.println(F("Insert new card..."));
}
