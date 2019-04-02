#include "RFID_Utils.h"

/*
 * A0 A1 A2 A3 A4 A5 
 */
void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
} // End dump_byte_array()
/*
 * FFFFFFFFFFFF
 */
void dump_byte_array2(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? "0" : "");
    Serial.print(buffer[i], HEX);
  }
} // End dump_byte_array2()
/*
 * 00 01 02 03 04 05 06 07
 * 08 09 0A 0B 0C 0D 0E 0F
 */
void dump_byte_array3(byte *buffer, int bufferSize, byte blockSize) {
  for (int i = 0; i < bufferSize; i++) {
    if ((i > 0) && (i % blockSize == 0)) {
      Serial.println();
    }
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
  Serial.println();
} // End dump_byte_array3()
/*
 * {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
 */
void dump_byte_array4(byte *buffer, byte bufferSize) {
  Serial.print(F(" {"));
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? "0x0" : "0x");
    Serial.print(buffer[i], HEX);
    Serial.print(i == (bufferSize - 1) ? "" : ", ");
  }
  Serial.print(F("}"));
} // End dump_byte_array4()




/*
 * Try to authenticate one time
 */
bool authenticateWithKeyBlockCommand(byte *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose)
{
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    key.keyByte[i] = p_key[i];
  }
  return authenticateWithKeyBlockCommand(&key, p_block, p_command, p_mfrc522, p_verbose);
}
bool authenticateWithKeyBlockCommand(MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose)
{
  bool isAuthenticated = false;

  p_mfrc522.PCD_Init();         // Init MFRC522 card
  if (p_mfrc522.PICC_IsNewCardPresent()) {
    if (p_verbose) {
      Serial.println(F("PICC_IsNewCardPresent() == true"));
    }
    // Select one of the cards
    if (p_mfrc522.PICC_ReadCardSerial()) {
      if (p_verbose) {
        Serial.println(F("PICC_ReadCardSerial() == true"));
        Serial.print(F("Block: "));
        Serial.print(p_block);
        Serial.print(F(" Key "));
        if (p_command == MFRC522::PICC_CMD_MF_AUTH_KEY_A) {
          Serial.print(F("A: "));
        }
        else if (p_command == MFRC522::PICC_CMD_MF_AUTH_KEY_B) {
          Serial.print(F("B: "));
        }
        dump_byte_array2((*p_key).keyByte, MFRC522::MF_KEY_SIZE);
        Serial.println();
      }
      MFRC522::StatusCode status = p_mfrc522.PCD_Authenticate(p_command, p_block, p_key, &(p_mfrc522.uid));
      if (status == MFRC522::STATUS_OK) {
        if (p_verbose) {
          Serial.print(F("PCD_Authenticate() OK: "));
        }
        isAuthenticated = true;
      }
      else {
        if (p_verbose) {
          Serial.print(F("PCD_Authenticate() failed: "));
        }
      }
      if (p_verbose) {
        Serial.println(p_mfrc522.GetStatusCodeName(status));
      }
    }
  }

  return isAuthenticated;
}


/*
 * Try to authenticate n times
 */
bool tryAuthenticateWithKeyBlockCommand(byte p_nbAttempt, byte *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose)
{
    MFRC522::MIFARE_Key key;
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    key.keyByte[i] = p_key[i];
  }
  return tryAuthenticateWithKeyBlockCommand(p_nbAttempt, &key, p_block, p_command, p_mfrc522, p_verbose);
}
bool tryAuthenticateWithKeyBlockCommand(byte p_nbAttempt, MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose)
{
  bool isAuthenticated = false;
  
  for (byte n = 0; n < p_nbAttempt && !isAuthenticated; n++) {
    isAuthenticated = authenticateWithKeyBlockCommand(p_key, p_block, p_command, p_mfrc522, p_verbose);
  }

  return isAuthenticated;
}

/*
 * 1. Authenticate
 * 2. Read Block
 */
bool readBlock(byte *p_key, byte p_block, byte p_command,byte *p_buffer, byte *p_bufferSize, MFRC522 p_mfrc522, bool p_verbose)
{
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    key.keyByte[i] = p_key[i];
  }
  return readBlock(&key, p_block, p_command, p_buffer, p_bufferSize, p_mfrc522, p_verbose);
}
bool readBlock(MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command, byte *p_buffer, byte *p_bufferSize, MFRC522 p_mfrc522, bool p_verbose)
{
  bool isAuthenticated = false;
  bool isSuccessRead = false;

  isAuthenticated = tryAuthenticateWithKeyBlockCommand(2, p_key, p_block, p_command, p_mfrc522, p_verbose);
  if (isAuthenticated) {
    MFRC522::StatusCode status = p_mfrc522.MIFARE_Read(p_block, p_buffer, p_bufferSize);
    if (status == MFRC522::STATUS_OK) {
      if (p_verbose) {
        Serial.print(F("MIFARE_Read() OK: "));
      }
      isSuccessRead = true;
    }
    else {
      if (p_verbose) {
        Serial.print(F("MIFARE_Read() failed: "));
      }
    }
    if (p_verbose) {
      Serial.println(p_mfrc522.GetStatusCodeName(status));
    }
    if (isSuccessRead) {
      if (p_verbose) {
        dump_byte_array(p_buffer, *p_bufferSize);
        Serial.println();
      }
    }
  }
  
  return isSuccessRead;
}

/*
 * 1. Authenticate
 * 2. Write Block
 */
bool writeBlock(byte *p_key, byte p_block, byte p_command, byte *p_buffer, byte p_bufferSize, MFRC522 p_mfrc522, bool p_verbose)
{
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    key.keyByte[i] = p_key[i];
  }
  return writeBlock(&key, p_block, p_command, p_buffer, p_bufferSize, p_mfrc522, p_verbose);
}
bool writeBlock(MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command, byte *p_buffer, byte p_bufferSize, MFRC522 p_mfrc522, bool p_verbose)
{
  if (p_block % 4 == 3) {
    byte byte7OfSectorTrailer = p_buffer[7];
    byte byte8OfSectorTrailer = p_buffer[8];
    struct_accessBits accessBits;
    getAccessBits(p_block, byte7OfSectorTrailer, byte8OfSectorTrailer, &accessBits);
    if (!canAccessBitsBeWrittenWithKeyA(&accessBits) && !canAccessBitsBeWrittenWithKeyB(&accessBits)) {
      Serial.println(); Serial.println();
      Serial.println(F("Not permited. Lock writing with KeyA and KeyB !!!"));
      Serial.println(); Serial.println();
      return false;
    }
  }
  if (p_block == 0) {
    Serial.println(); Serial.println();
    Serial.println(F("Not implemented : Write Block 0 !!!"));
    Serial.println(); Serial.println();
    return false;
  }
  bool isAuthenticated = false;
  bool isSuccessWrite = false;

  isAuthenticated = tryAuthenticateWithKeyBlockCommand(2, p_key, p_block, p_command, p_mfrc522, p_verbose);
  if (isAuthenticated) {
    MFRC522::StatusCode status = p_mfrc522.MIFARE_Write(p_block, p_buffer, p_bufferSize);
    if (status == MFRC522::STATUS_OK) {
      if (p_verbose) {
        Serial.print(F("MIFARE_Write() OK: "));
      }
      isSuccessWrite = true;
    }
    else {
      if (p_verbose) {
        Serial.print(F("MIFARE_Write() failed: "));
      }
    }
    if (p_verbose) {
      Serial.println(p_mfrc522.GetStatusCodeName(status));
    }
    if (isSuccessWrite) {
      if (p_verbose) {
        dump_byte_array(p_buffer, p_bufferSize);
        Serial.println();
      }
    }
  }
  
  return isSuccessWrite;
}


bool canDataBlockBeReadWithKeyA(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canDataBlockBeReadWithKeyB(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canDataBlockBeWrittenWithKeyA(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canDataBlockBeWrittenWithKeyB(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canKeyABeWrittenWithKeyA(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canKeyABeWrittenWithKeyB(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canAccessBitsBeWrittenWithKeyA(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canAccessBitsBeWrittenWithKeyB(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canKeyBBeWrittenWithKeyA(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}
bool canKeyBBeWrittenWithKeyB(struct_accessBits *p_accessBits) {
  bool ret = false;
  
  if (!p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 && !p_accessBits->c2 && !p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 &&  p_accessBits->c2 && !p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if (!p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = true;
  if ( p_accessBits->c1 && !p_accessBits->c2 &&  p_accessBits->c3) ret = false;
  if ( p_accessBits->c1 &&  p_accessBits->c2 &&  p_accessBits->c3) ret = false;

  return ret;
}

/*
 * 
 */
bool formatSector(byte *p_keyA, byte *p_keyB, byte p_sector, MFRC522 p_mfrc522, bool p_verbose) {
  bool ret = false;
  
  byte sector_trailer = (p_sector << 2) + 3;
  byte buffer[BLOCK_SIZE_CRC];
  byte bufferSize = sizeof(buffer);
  bool isSuccessRead = readBlock(p_keyA, sector_trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_A, buffer, &bufferSize, p_mfrc522, p_verbose);
  if (!isSuccessRead) {
    Serial.print(F("Can't read sector trailer of Sector : "));
    Serial.println(p_sector, DEC);
    Serial.print(F("With KeyA : "));
    dump_byte_array(p_keyA, MFRC522::MF_KEY_SIZE);
    Serial.println();
    return false;
  }
  byte byte7OfSectorTrailer = buffer[7];
  byte byte8OfSectorTrailer = buffer[8];
  struct_accessBits accessBits;
  getAccessBits(sector_trailer, byte7OfSectorTrailer, byte8OfSectorTrailer, &accessBits);
  if (!canAccessBitsBeWrittenWithKeyA(&accessBits) && !canAccessBitsBeWrittenWithKeyB(&accessBits)) {
    Serial.println();
    Serial.println();
    Serial.print(F("Can't format Sector "));
    Serial.print(p_sector, DEC);
    Serial.println(F(" !!!"));
    Serial.println(F("Access Bits not writable !!!"));
    return false;
  }
  // c13=0, c23=1, c33=1  OR  c13=1, c23=0, c33=1 (KeyB can write AccessBits)
  if (canAccessBitsBeWrittenWithKeyB(&accessBits)) {
    // {0x??, 0x??, 0x??, 0x??, 0x??, 0x??, 0xFF, 0x07, 0x80, 0x69, 0x??, 0x??, 0x??, 0x??, 0x??, 0x??};
    for (byte i=0; i<MFRC522::MF_KEY_SIZE; i++) {
      buffer[i] = p_keyA[i];
      buffer[MFRC522::MF_KEY_SIZE + 4 + i] = p_keyB[i];
    }
    // c13=0, c23=0, c33=1 (transport configuration)
    buffer[MFRC522::MF_KEY_SIZE] = 0xFF;
    buffer[MFRC522::MF_KEY_SIZE + 1] = 0x07;
    buffer[MFRC522::MF_KEY_SIZE + 2] = 0x80;
    buffer[MFRC522::MF_KEY_SIZE + 3] = 0x69;
//Serial.println(F("Try to write "));
//dump_byte_array(buffer, sizeof(buffer));
//Serial.println();
    ret = writeBlock(p_keyB, sector_trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_B, buffer, BLOCK_SIZE, p_mfrc522, p_verbose);
  }
  byte defaultKey[MFRC522::MF_KEY_SIZE];
  // {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
  for (byte i=0; i<MFRC522::MF_KEY_SIZE; i++) {
    defaultKey[i] = 0xFF;
    buffer[i] = 0xFF;
    buffer[MFRC522::MF_KEY_SIZE + 4 + i] = 0xFF;
  }
  buffer[MFRC522::MF_KEY_SIZE] = 0xFF;
  buffer[MFRC522::MF_KEY_SIZE + 1] = 0x07;
  buffer[MFRC522::MF_KEY_SIZE + 2] = 0x80;
  buffer[MFRC522::MF_KEY_SIZE + 3] = 0x69;
//Serial.println(F("Try to write "));
//dump_byte_array(buffer, sizeof(buffer));
//Serial.println();
  ret = writeBlock(p_keyA, sector_trailer, MFRC522::PICC_CMD_MF_AUTH_KEY_A, buffer, BLOCK_SIZE, p_mfrc522, p_verbose);
  for (byte i=0; i<BLOCK_SIZE; i++) {
    buffer[i] = 0x00;
  }
  byte block = (p_sector << 2);
  for (byte i=0; i<3; i++) {
    ret = writeBlock(defaultKey, block + i, MFRC522::PICC_CMD_MF_AUTH_KEY_A, buffer, BLOCK_SIZE, p_mfrc522, p_verbose);
  }
  
  return ret;
}


void getAccessBits(byte p_block, byte p_byte7OfSectorTrailer, byte p_byte8OfSectorTrailer, struct_accessBits *p_accessBits) {
  byte block_in_sector = p_block % BLOCK_PER_SECTOR;
  if (block_in_sector == 3) {             // Sector Trailer
    p_accessBits->c1 = bitRead(p_byte7OfSectorTrailer, 7);  // c13
    p_accessBits->c2 = bitRead(p_byte8OfSectorTrailer, 3);  // c23
    p_accessBits->c3 = bitRead(p_byte8OfSectorTrailer, 7);  // c33
  }
  else if (block_in_sector == 2) {        // Data Block
    p_accessBits->c1 = bitRead(p_byte7OfSectorTrailer, 6);  // c12
    p_accessBits->c2 = bitRead(p_byte8OfSectorTrailer, 2);  // c22
    p_accessBits->c3 = bitRead(p_byte8OfSectorTrailer, 6);  // c32
  }
  else if (block_in_sector == 1) {        // Data Block
    p_accessBits->c1 = bitRead(p_byte7OfSectorTrailer, 5);  // c11
    p_accessBits->c2 = bitRead(p_byte8OfSectorTrailer, 1);  // c21
    p_accessBits->c3 = bitRead(p_byte8OfSectorTrailer, 5);  // c31
  }
  else { // if (block_in_sector == 0) {   // Data Block
    p_accessBits->c1 = bitRead(p_byte7OfSectorTrailer, 4);  // c10
    p_accessBits->c2 = bitRead(p_byte8OfSectorTrailer, 0);  // c20
    p_accessBits->c3 = bitRead(p_byte8OfSectorTrailer, 4);  // c30
  }

  return;
}
