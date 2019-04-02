#ifndef RFID_UTILS_h
#define RFID_UTILS_h

#include <Arduino.h>
#include <MFRC522.h>

#define SECTOR_NUMBER    16
#define BLOCK_NUMBER     64
#define BLOCK_PER_SECTOR 4
#define BLOCK_SIZE       16
#define BLOCK_SIZE_CRC   18
#define DUMP_SIZE        1024

typedef struct {
  byte key[MFRC522::MF_KEY_SIZE];
  byte block;
  byte command;                   //  MFRC522::PICC_CMD_MF_AUTH_KEY_A  /  MFRC522::PICC_CMD_MF_AUTH_KEY_B
  byte content[BLOCK_SIZE];
} struct_blockDetailed;

typedef struct {
  bool c1;
  bool c2;
  bool c3;
} struct_accessBits;


void dump_byte_array(byte *buffer, byte bufferSize);
void dump_byte_array2(byte *buffer, byte bufferSize);
void dump_byte_array3(byte *buffer, int bufferSize, byte blockSize);
void dump_byte_array4(byte *buffer, byte bufferSize);

bool authenticateWithKeyBlockCommand(byte *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose);
bool authenticateWithKeyBlockCommand(MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose);
bool tryAuthenticateWithKeyBlockCommand(byte p_nbAttempt, byte *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose);
bool tryAuthenticateWithKeyBlockCommand(byte p_nbAttempt, MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command, MFRC522 p_mfrc522, bool p_verbose);

bool readBlock(byte *p_key, byte p_block, byte p_command,byte *p_buffer, byte *p_bufferSize, MFRC522 p_mfrc522, bool p_verbose);
bool readBlock(MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command,byte *p_buffer, byte *p_bufferSize, MFRC522 p_mfrc522, bool p_verbose);
bool writeBlock(byte *p_key, byte p_block, byte p_command,byte *p_buffer, byte p_bufferSize, MFRC522 p_mfrc522, bool p_verbose);
bool writeBlock(MFRC522::MIFARE_Key *p_key, byte p_block, byte p_command,byte *p_buffer, byte p_bufferSize, MFRC522 p_mfrc522, bool p_verbose);

bool canDataBlockBeReadWithKeyA(struct_accessBits *p_accessBits);
bool canDataBlockBeReadWithKeyB(struct_accessBits *p_accessBits);
bool canDataBlockBeWrittenWithKeyA(struct_accessBits *p_accessBits);
bool canDataBlockBeWrittenWithKeyB(struct_accessBits *p_accessBits);
bool canKeyABeWrittenWithKeyA(struct_accessBits *p_accessBits);
bool canKeyABeWrittenWithKeyB(struct_accessBits *p_accessBits);
bool canAccessBitsBeWrittenWithKeyA(struct_accessBits *p_accessBits);
bool canAccessBitsBeWrittenWithKeyB(struct_accessBits *p_accessBits);
bool canKeyBBeWrittenWithKeyA(struct_accessBits *p_accessBits);
bool canKeyBBeWrittenWithKeyB(struct_accessBits *p_accessBits);

bool formatSector(byte *p_keyA, byte *p_keyB, byte p_sector, MFRC522 p_mfrc522, bool p_verbose);
void getAccessBits(byte p_block, byte p_byte7OfSectorTrailer, byte p_byte8OfSectorTrailer, struct_accessBits *p_accessBits);

#endif
