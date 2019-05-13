#ifndef RFID_MYKNOWNKEYS_h
#define RFID_MYKNOWNKEYS_h

#include <MFRC522.h>

// Known keys, see: https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys

const byte knownKeys0[][MFRC522::MF_KEY_SIZE] =  {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // FF FF FF FF FF FF = factory default
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}, // A0 A1 A2 A3 A4 A5
    {0x41, 0x42, 0x43, 0x44, 0x45, 0x46}
};

/**
 * '#' ==> '//'
 * ',--' ==> ', // '
 * ', --' ==> ', // '
 * ',//' ==> ', //'
 * '\t' ==> ' '
 * '   ' ==> ' '
 * '  ' ==> ' '
 * ' \r\n' ==> '\r\n'
 * '^[0-F]{12}$' ==> '$&,'
 * '^[0-F]{12},' ==> '0x$&'
 * '[0-F]{10},' ==> ', 0x$&'
 * '[0-F]{8},' ==> ', 0x$&'
 * '[0-F]{4},' ==> ', 0x$&'
 * '^0x[0-F]{2}, 0x[0-F]{2}, 0x[0-F]{2}, 0x[0-F]{2}, 0x[0-F]{2}' ==> '$&, 0x'
 * 
 **/
const byte knownKeys[] PROGMEM =  {
//
// Mifare Default Keys
// -- iceman fork version --
// -- contribute to this list, sharing is caring --
//
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Defaultkey(firstkeyusedbyprogramifnouserdefinedkey)
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blankkey
0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, // NFCForumMADkey
0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7, // key A Wien
0x5a, 0x1b, 0x85, 0xfc, 0xe2, 0x0a, // key B Wien
0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97,
0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f,
0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91,
0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6,
0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9,
//
// more Keys from mf_default_keys.lua
0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
0x00, 0x00, 0x0f, 0xfe, 0x24, 0x88, // VästtrafikenKeyB
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
0x02, 0x97, 0x92, 0x7c, 0x0f, 0x77, // VästtrafikenKeyA
0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
0x12, 0xf2, 0xee, 0x34, 0x78, 0xc1,
0x14, 0xd4, 0x46, 0xe3, 0x33, 0x63,
0x19, 0x99, 0xa3, 0x55, 0x4a, 0x55,
0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
0x26, 0x94, 0x0b, 0x21, 0xff, 0x5d, // RKFSLKeyA
0x27, 0xdd, 0x91, 0xf1, 0xfc, 0xf1,
0x2B, 0xA9, 0x62, 0x1E, 0x0A, 0x36, // DirectoryandeventlogKeyB
0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
0x33, 0xf9, 0x74, 0xb4, 0x27, 0x69,
0x34, 0xd1, 0xdf, 0x99, 0x34, 0xc5,
0x43, 0x4f, 0x4d, 0x4d, 0x4f, 0x41, // RKFJOJOGROUPKeyA
0x43, 0x4f, 0x4d, 0x4d, 0x4f, 0x42, // RKFJOJOGROUPKeyB
0x43, 0xab, 0x19, 0xef, 0x5c, 0x31,
0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
0x47, 0x52, 0x4f, 0x55, 0x50, 0x41, // RKFJOJOGROUPKeyA
0x47, 0x52, 0x4f, 0x55, 0x50, 0x42, // RKFJOJOGROUPKeyB
0x4A, 0xF9, 0xD7, 0xAD, 0xEB, 0xE4, // DirectoryandeventlogKeyA
0x4b, 0x0b, 0x20, 0x10, 0x7c, 0xcb, // TNP3xxx
0x50, 0x52, 0x49, 0x56, 0x41, 0x41, // RKFJOJOPRIVAKeyA
0x50, 0x52, 0x49, 0x56, 0x41, 0x42, // RKFJOJOPRIVAKeyB
0x50, 0x52, 0x49, 0x56, 0x54, 0x41,
0x50, 0x52, 0x49, 0x56, 0x54, 0x42,
0x54, 0x72, 0x61, 0x76, 0x65, 0x6c, // VästtrafikenKeyA
0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
0x55, 0xf5, 0xa5, 0xdd, 0x38, 0xc9,
0x56, 0x93, 0x69, 0xc5, 0xa0, 0xe5, // kiev
0x5c, 0x59, 0x8c, 0x9c, 0x58, 0xb5, // RKFSLKeyB
0x63, 0x21, 0x93, 0xbe, 0x1c, 0x3c, // kiev
0x64, 0x46, 0x72, 0xbd, 0x4a, 0xfe, // kiev
0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
0x72, 0x2b, 0xfc, 0xc5, 0x37, 0x5f, // RKFRejskortDanmarkKeyA
0x77, 0x69, 0x74, 0x68, 0x75, 0x73, // VästtrafikenKeyB
0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
0x8f, 0xe6, 0x44, 0x03, 0x87, 0x90, // kiev
0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
0x99, 0xc6, 0x36, 0x33, 0x44, 0x33,
0x9d, 0xe8, 0x9e, 0x07, 0x02, 0x77, // kiev
0xa0, 0x00, 0x00, 0x00, 0x00, 0x00,
0xa0, 0x53, 0xa2, 0x92, 0xa4, 0xaf,
0xa6, 0x45, 0x98, 0xa7, 0x74, 0x78, // RKFSLKeyA
0xa9, 0x41, 0x33, 0x01, 0x34, 0x01,
0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, // Keyfromladyada.net
0xb0, 0x00, 0x00, 0x00, 0x00, 0x00,
0xb1, 0x27, 0xc6, 0xf4, 0x14, 0x36,
0xb5, 0xff, 0x67, 0xcb, 0xa9, 0x51, // kiev
0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
0xbd, 0x49, 0x3a, 0x39, 0x62, 0xb6,
0xc9, 0x34, 0xfe, 0x34, 0xd9, 0x34,
0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
0xe4, 0xd2, 0x77, 0x0a, 0x89, 0xbe, // RKFSLKeyB
0xee, 0x00, 0x42, 0xf8, 0x88, 0x40, // VästtrafikenKeyB
0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
0xef, 0xf6, 0x03, 0xe1, 0xef, 0xe9, // kiev
0xf1, 0x4e, 0xe7, 0xca, 0xe8, 0x63, // kiev
0xf1, 0xa9, 0x73, 0x41, 0xa9, 0xfc,
0xf1, 0xd8, 0x3f, 0x96, 0x43, 0x14, // RKFRejskortDanmarkKeyB
0xfc, 0x00, 0x01, 0x87, 0x78, 0xf7, // VästtrafikenKeyA, RKFÖstgötaTrafikenKeyA
0x44, 0xab, 0x09, 0x01, 0x08, 0x45, // hotel system
0x85, 0xfe, 0xd9, 0x80, 0xea, 0x5a, // hotel system
0x31, 0x4B, 0x49, 0x47, 0x49, 0x56, // VIGIK1KeyA
0x56, 0x4c, 0x50, 0x5f, 0x4d, 0x41, // VIGIK1KeyB
0xba, 0x5b, 0x89, 0x5d, 0xa1, 0x62, // VIGIK1KeyB
//
// Data from: http://irq5.io/2013/04/13/decoding-bcard-conference-badges/
0xf4, 0xa9, 0xef, 0x2a, 0xfc, 0x6d, // BCARD KeyB
//
//
0xa9, 0xf9, 0x53, 0xde, 0xf0, 0xa3, //
0x75, 0xcc, 0xb5, 0x9c, 0x9b, 0xed, // mystery KeyA Mifare 1k EV1 (S50) Sector 17!
0x4b, 0x79, 0x1b, 0xea, 0x7b, 0xcc, // mystery KeyB Mifare 1k EV1 (S50) Sector 17!
//
// Here be BIP keys...
0x3A, 0x42, 0xF3, 0x3A, 0xF4, 0x29,
0x1F, 0xC2, 0x35, 0xAC, 0x13, 0x09,
0x63, 0x38, 0xA3, 0x71, 0xC0, 0xED,
0x24, 0x3F, 0x16, 0x09, 0x18, 0xD1,
0xF1, 0x24, 0xC2, 0x57, 0x8A, 0xD0,
0x9A, 0xFC, 0x42, 0x37, 0x2A, 0xF1,
0x32, 0xAC, 0x3B, 0x90, 0xAC, 0x13,
0x68, 0x2D, 0x40, 0x1A, 0xBB, 0x09,
0x4A, 0xD1, 0xE2, 0x73, 0xEA, 0xF1,
0x06, 0x7D, 0xB4, 0x54, 0x54, 0xA9,
0xE2, 0xC4, 0x25, 0x91, 0x36, 0x8A,
0x15, 0xFC, 0x4C, 0x76, 0x13, 0xFE,
0x2A, 0x3C, 0x34, 0x7A, 0x12, 0x00,
0x68, 0xD3, 0x02, 0x88, 0x91, 0x0A,
0x16, 0xF3, 0xD5, 0xAB, 0x11, 0x39,
0xF5, 0x9A, 0x36, 0xA2, 0x54, 0x6D,
0x93, 0x7A, 0x4F, 0xFF, 0x30, 0x11,
0x64, 0xE3, 0xC1, 0x03, 0x94, 0xC2,
0x35, 0xC3, 0xD2, 0xCA, 0xEE, 0x88,
0xB7, 0x36, 0x41, 0x26, 0x14, 0xAF,
0x69, 0x31, 0x43, 0xF1, 0x03, 0x68,
0x32, 0x4F, 0x5D, 0xF6, 0x53, 0x10,
0xA3, 0xF9, 0x74, 0x28, 0xDD, 0x01,
0x64, 0x3F, 0xB6, 0xDE, 0x22, 0x17,
0x63, 0xF1, 0x7A, 0x44, 0x9A, 0xF0,
0x82, 0xF4, 0x35, 0xDE, 0xDF, 0x01,
0xC4, 0x65, 0x2C, 0x54, 0x26, 0x1C,
0x02, 0x63, 0xDE, 0x12, 0x78, 0xF3,
0xD4, 0x9E, 0x28, 0x26, 0x66, 0x4F,
0x51, 0x28, 0x4C, 0x36, 0x86, 0xA6,
0x3D, 0xF1, 0x4C, 0x80, 0x00, 0xA1,
0x6A, 0x47, 0x0D, 0x54, 0x12, 0x7C,
//
// Data from: http://pastebin.com/AK9Bftpw
0x48, 0xff, 0xe7, 0x12, 0x94, 0xa0, // Länstrafiken i Västerbotten
0xe3, 0x42, 0x92, 0x81, 0xef, 0xc1, // Länstrafiken i Västerbotten
0x16, 0xf2, 0x1a, 0x82, 0xec, 0x84, // Länstrafiken i Västerbotten
0x46, 0x07, 0x22, 0x12, 0x25, 0x10, // Länstrafiken i Västerbotten
//
// 3dprinter
0xAA, 0xFB, 0x06, 0x04, 0x58, 0x77, // EPI Envisionte// 3dprinter
//
// gym
0x3e, 0x65, 0xe4, 0xfb, 0x65, 0xb3, // Fysiken A
0x25, 0x09, 0x4d, 0xf6, 0xf1, 0x48, // Fysiken B
//
// 24-7
0xD2, 0x17, 0x62, 0xB2, 0xDE, 0x3B,
0x0E, 0x83, 0xA3, 0x74, 0xB5, 0x13,
0x1F, 0x1F, 0xFE, 0x00, 0x00, 0x00,
0xA1, 0x0F, 0x30, 0x3F, 0xC8, 0x79,
0x13, 0x22, 0x28, 0x52, 0x30, 0xb8,
0x0C, 0x71, 0xBC, 0xFB, 0x7E, 0x72,
0xC3, 0xC8, 0x8C, 0x63, 0x40, 0xB8,
0xF1, 0x01, 0x62, 0x27, 0x50, 0xB7,
0x1F, 0x10, 0x73, 0x28, 0xDC, 0x8D,
0x71, 0x07, 0x32, 0x20, 0x0D, 0x34,
0x7C, 0x33, 0x5F, 0xB1, 0x21, 0xB5,
0xB3, 0x9A, 0xE1, 0x74, 0x35, 0xDC,
//
//
0x45, 0x48, 0x41, 0x58, 0x54, 0x43, // key A
//
// Data from: http://pastebin.com/gQ6nk38G
0xD3, 0x9B, 0xB8, 0x3F, 0x52, 0x97,
0xA2, 0x7D, 0x38, 0x04, 0xC2, 0x59,
0x85, 0x67, 0x5B, 0x20, 0x00, 0x17,
0x52, 0x8C, 0x9D, 0xFF, 0xE2, 0x8C,
0xC8, 0x2E, 0xC2, 0x9E, 0x32, 0x35,
0x3E, 0x35, 0x54, 0xAF, 0x0E, 0x12,
0x49, 0x1C, 0xDC, 0xFB, 0x77, 0x52,
0x22, 0xC1, 0xBA, 0xE1, 0xAA, 0xCD,
0x5F, 0x14, 0x67, 0x16, 0xE3, 0x73,
0x74, 0x0E, 0x9A, 0x4F, 0x9A, 0xAF,
0xAC, 0x0E, 0x24, 0xC7, 0x55, 0x27,
0x97, 0x18, 0x4D, 0x13, 0x62, 0x33,
0xE4, 0x44, 0xD5, 0x3D, 0x35, 0x9F,
0x17, 0x75, 0x88, 0x56, 0xB1, 0x82,
0xA8, 0x96, 0x6C, 0x7C, 0xC5, 0x4B,
0xC6, 0xAD, 0x00, 0x25, 0x45, 0x62,
0xAE, 0x3F, 0xF4, 0xEE, 0xA0, 0xDB,
0x5E, 0xB8, 0xF8, 0x84, 0xC8, 0xD1,
0xFE, 0xE4, 0x70, 0xA4, 0xCB, 0x58,
0x75, 0xD8, 0x69, 0x0F, 0x21, 0xB6,
0x87, 0x1B, 0x8C, 0x08, 0x59, 0x97,
0x97, 0xD1, 0x10, 0x1F, 0x18, 0xB0,
0x75, 0xED, 0xE6, 0xA8, 0x44, 0x60,
0xDF, 0x27, 0xA8, 0xF1, 0xCB, 0x8E,
0xB0, 0xC9, 0xDD, 0x55, 0xDD, 0x4D,
//
// Data from: http://bit.ly/1bdSbJl
0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1,
//
// Data from: msk three
0xae, 0x3d, 0x65, 0xa3, 0xda, 0xd4,
0xa7, 0x3f, 0x5d, 0xc1, 0xd3, 0x33,
//
// Data from: msk social
0x27, 0x35, 0xfc, 0x18, 0x18, 0x07,
0x2a, 0xba, 0x95, 0x19, 0xf5, 0x74,
0x84, 0xfd, 0x7f, 0x7a, 0x12, 0xb6,
0x73, 0x06, 0x8f, 0x11, 0x8c, 0x13,
0x18, 0x6d, 0x8c, 0x4b, 0x93, 0xf9,
0x3a, 0x4b, 0xba, 0x8a, 0xda, 0xf0,
0x87, 0x65, 0xb1, 0x79, 0x68, 0xa2,
0x40, 0xea, 0xd8, 0x07, 0x21, 0xce,
0x0d, 0xb5, 0xe6, 0x52, 0x3f, 0x7c,
0x51, 0x11, 0x9d, 0xae, 0x52, 0x16,
0x83, 0xe3, 0x54, 0x9c, 0xe4, 0x2d,
0x13, 0x6b, 0xdb, 0x24, 0x6c, 0xac,
0x7d, 0xe0, 0x2a, 0x7f, 0x60, 0x25,
0xbf, 0x23, 0xa5, 0x3c, 0x1f, 0x63,
0xcb, 0x9a, 0x1f, 0x2d, 0x73, 0x68,
0xc7, 0xc0, 0xad, 0xb3, 0x28, 0x4f,
0x2b, 0x7f, 0x32, 0x53, 0xfa, 0xc5,
0x9f, 0x13, 0x1d, 0x8c, 0x20, 0x57,
0x67, 0x36, 0x2d, 0x90, 0xf9, 0x73,
0x62, 0x02, 0xa3, 0x8f, 0x69, 0xe2,
0x10, 0x05, 0x33, 0xb8, 0x93, 0x31,
0x65, 0x3a, 0x87, 0x59, 0x40, 0x79,
0xd8, 0xa2, 0x74, 0xb2, 0xe0, 0x26,
0xb2, 0x0b, 0x83, 0xcb, 0x14, 0x5c,
0x9a, 0xfa, 0x6c, 0xb4, 0xfc, 0x3d,
//
// Data from http://pastebin.com/RRJUEDCM
0x0d, 0x25, 0x8f, 0xe9, 0x02, 0x96,
0xe5, 0x5a, 0x3c, 0xa7, 0x18, 0x26,
0xa4, 0xf2, 0x04, 0x20, 0x3f, 0x56,
0xee, 0xb4, 0x20, 0x20, 0x9d, 0x0c,
0x91, 0x1e, 0x52, 0xfd, 0x7c, 0xe4,
0x75, 0x2f, 0xbb, 0x5b, 0x7b, 0x45,
0x66, 0xb0, 0x3a, 0xca, 0x6e, 0xe9,
0x48, 0x73, 0x43, 0x89, 0xed, 0xc3,
0x17, 0x19, 0x37, 0x09, 0xad, 0xf4,
0x1a, 0xcc, 0x31, 0x89, 0x57, 0x8c,
0xc2, 0xb7, 0xec, 0x7d, 0x4e, 0xb1,
0x36, 0x9a, 0x46, 0x63, 0xac, 0xd2,
//
// Data from https://github.com/zhangjingye03/zxcardumper
// zxcard Key A/B
0x66, 0x87, 0x70, 0x66, 0x66, 0x44,
0x00, 0x30, 0x03, 0x00, 0x30, 0x03,
//
// Data from: http://phreakerclub.com/forum/showthread.php?p=41266
0x26, 0x97, 0x3e, 0xa7, 0x43, 0x21,
0x71, 0xf3, 0xa3, 0x15, 0xad, 0x26,
0x51, 0x04, 0x4e, 0xfb, 0x5a, 0xab,
0xac, 0x70, 0xca, 0x32, 0x7a, 0x04,
0xeb, 0x0a, 0x8f, 0xf8, 0x8a, 0xde,
//
// Data from: https://github.com/RadioWar/NFCGUI
0x44, 0xdd, 0x5a, 0x38, 0x5a, 0xaf,
0x21, 0xa6, 0x00, 0x05, 0x6c, 0xb0,
0xb1, 0xac, 0xa3, 0x31, 0x80, 0xa5,
0xdd, 0x61, 0xeb, 0x6b, 0xce, 0x22,
0x15, 0x65, 0xa1, 0x72, 0x77, 0x0f,
0x3e, 0x84, 0xd2, 0x61, 0x2e, 0x2a,
0xf2, 0x34, 0x42, 0x43, 0x67, 0x65,
0x79, 0x67, 0x4f, 0x96, 0xc7, 0x71,
0x87, 0xdf, 0x99, 0xd4, 0x96, 0xcb,
0xc5, 0x13, 0x2c, 0x89, 0x80, 0xbc,
0xa2, 0x16, 0x80, 0xc2, 0x77, 0x73,
0xf2, 0x6e, 0x21, 0xed, 0xce, 0xe2,
0x67, 0x55, 0x57, 0xec, 0xc9, 0x2e,
0xf4, 0x39, 0x6e, 0x46, 0x81, 0x14,
0x6d, 0xb1, 0x7c, 0x16, 0xb3, 0x5b,
0x41, 0x86, 0x56, 0x2a, 0x5b, 0xb2,
0x2f, 0xea, 0xe8, 0x51, 0xc1, 0x99,
0xdb, 0x1a, 0x33, 0x38, 0xb2, 0xeb,
0x15, 0x7b, 0x10, 0xd8, 0x4c, 0x6b,
0xa6, 0x43, 0xf9, 0x52, 0xea, 0x57,
0xdf, 0x37, 0xdc, 0xb6, 0xaf, 0xb3,
0x4c, 0x32, 0xba, 0xf3, 0x26, 0xe0,
0x91, 0xce, 0x16, 0xc0, 0x7a, 0xc5,
0x3c, 0x5d, 0x1c, 0x2b, 0xcd, 0x18,
0xc3, 0xf1, 0x9e, 0xc5, 0x92, 0xa2,
0xf7, 0x2a, 0x29, 0x00, 0x54, 0x59,
0x18, 0x5f, 0xa3, 0x43, 0x89, 0x49,
0x32, 0x1a, 0x69, 0x5b, 0xd2, 0x66,
0xd3, 0x27, 0x08, 0x3a, 0x60, 0xa7,
0x45, 0x63, 0x5e, 0xf6, 0x6e, 0xf3,
0x54, 0x81, 0x98, 0x6d, 0x2d, 0x62,
0xcb, 0xa6, 0xae, 0x86, 0x9a, 0xd5,
0x64, 0x5a, 0x16, 0x6b, 0x1e, 0xeb,
0xa7, 0xab, 0xbc, 0x77, 0xcc, 0x9e,
0xf7, 0x92, 0xc4, 0xc7, 0x6a, 0x5c,
0xbf, 0xb6, 0x79, 0x6a, 0x11, 0xdb,
//
// Data from Salto A/B
0x6A, 0x19, 0x87, 0xC4, 0x0A, 0x21,
0x7F, 0x33, 0x62, 0x5B, 0xC1, 0x29,
//
// Data from forum
0x23, 0x38, 0xb4, 0x91, 0x31, 0x11,
//
// Data from stoye
0xcb, 0x77, 0x9c, 0x50, 0xe1, 0xbd,
0xa2, 0x7d, 0x38, 0x04, 0xc2, 0x59,
0x00, 0x3c, 0xc4, 0x20, 0x00, 0x1a,
0xf9, 0x86, 0x15, 0x26, 0x13, 0x0f,
0x38, 0x1e, 0xce, 0x05, 0x0f, 0xbd,
0xa5, 0x71, 0x86, 0xbd, 0xd2, 0xb9,
0x48, 0xc7, 0x39, 0xe2, 0x1a, 0x04,
0x36, 0xab, 0xf5, 0x87, 0x4e, 0xd7,
0x64, 0x9d, 0x2a, 0xbb, 0xbd, 0x20,
0xbb, 0xe8, 0xff, 0xfc, 0xf3, 0x63,
0xab, 0x4e, 0x70, 0x45, 0xe9, 0x7d,
0x34, 0x0e, 0x40, 0xf8, 0x1c, 0xd8,
0xe4, 0xf6, 0x5c, 0x0e, 0xf3, 0x2c,
0xd2, 0xa5, 0x97, 0xd7, 0x69, 0x36,
0xa9, 0x20, 0xf3, 0x2f, 0xe9, 0x3a,
0x86, 0xaf, 0xd9, 0x52, 0x00, 0xf7,
0x9b, 0x83, 0x2a, 0x98, 0x81, 0xff,
0x26, 0x64, 0x39, 0x65, 0xb1, 0x6e,
0x0c, 0x66, 0x99, 0x93, 0xc7, 0x76,
0xb4, 0x68, 0xd1, 0x99, 0x1a, 0xf9,
0xd9, 0xa3, 0x78, 0x31, 0xdc, 0xe5,
0x2f, 0xc1, 0xf3, 0x2f, 0x51, 0xb1,
0x0f, 0xfb, 0xf6, 0x5b, 0x5a, 0x14,
0xc5, 0xcf, 0xe0, 0x6d, 0x9e, 0xa3,
0xc0, 0xde, 0xce, 0x67, 0x38, 0x29,
//
0xa5, 0x6c, 0x2d, 0xf9, 0xa2, 0x6d,
//
// Data from: https://pastebin.com/vbwast74
//
0x20, 0x31, 0xd1, 0xe5, 0x7a, 0x3b,
0x68, 0xd3, 0xf7, 0x30, 0x7c, 0x89,
0x91, 0x89, 0x44, 0x9e, 0xa2, 0x4e,
0x56, 0x8c, 0x90, 0x83, 0xf7, 0x1c, // Smart Rider. Western Australian Public Transport Cards
0x53, 0xc1, 0x1f, 0x90, 0x82, 0x2a,
// Vigik Keys
// Various sources :
// * https://github.com/DumpDos/Vigik
// * http://newffr.com/viewtopic.php?&forum=235&topic=11559
// * Own dumps
0x02, 0x12, 0x09, 0x19, 0x75, 0x91, // BTCINO UNDETERMINED SPREAKD 0x01->0x13 key
0x2e, 0xf7, 0x20, 0xf2, 0xaf, 0x76,
0x41, 0x4c, 0x41, 0x52, 0x4f, 0x4e,
0x42, 0x4c, 0x41, 0x52, 0x4f, 0x4e,
0x4a, 0x63, 0x52, 0x68, 0x46, 0x77,
0xbf, 0x1f, 0x44, 0x24, 0xaf, 0x76,
0x53, 0x66, 0x53, 0x64, 0x4c, 0x65,
//
// Intratone Cogelec
// Data from http://bouzdeck.com/rfid/32-cloning-a-mifare-classic-1k-tag.html
0x48, 0x45, 0x58, 0x41, 0x43, 0x54,
0xa2, 0x2a, 0xe1, 0x29, 0xc0, 0x13,
0x49, 0xfa, 0xe4, 0xe3, 0x84, 0x9f,
0x38, 0xfc, 0xf3, 0x30, 0x72, 0xe0,
0x8a, 0xd5, 0x51, 0x7b, 0x4b, 0x18,
0x50, 0x93, 0x59, 0xf1, 0x31, 0xb1,
0x6c, 0x78, 0x92, 0x8e, 0x13, 0x17,
0xaa, 0x07, 0x20, 0x01, 0x87, 0x38,
0xa6, 0xca, 0xc2, 0x88, 0x64, 0x12,
0x62, 0xd0, 0xc4, 0x24, 0xed, 0x8e,
0xe6, 0x4a, 0x98, 0x6a, 0x5d, 0x94,
0x8f, 0xa1, 0xd6, 0x01, 0xd0, 0xa2,
0x89, 0x34, 0x73, 0x50, 0xbd, 0x36,
0x66, 0xd2, 0xb7, 0xdc, 0x39, 0xef,
0x6b, 0xc1, 0xe1, 0xae, 0x54, 0x7d,
0x22, 0x72, 0x9a, 0x9b, 0xd4, 0x0f,
//
// Data from https://dfir.lu/blog/cloning-a-mifare-classic-1k-tag.html
0x92, 0x5b, 0x15, 0x8f, 0x79, 0x6f,
0xfa, 0xd6, 0x3e, 0xcb, 0x58, 0x91,
0xbb, 0xa8, 0x40, 0xba, 0x1c, 0x57,
0xcc, 0x6b, 0x3b, 0x3c, 0xd2, 0x63,
0x62, 0x45, 0xe4, 0x73, 0x52, 0xe6,
0x8e, 0xd4, 0x1e, 0x8b, 0x80, 0x56,
0x2d, 0xd3, 0x9a, 0x54, 0xe1, 0xf3,
0x6d, 0x4c, 0x5b, 0x36, 0x58, 0xd2,
0x18, 0x77, 0xed, 0x29, 0x43, 0x5a,
0x52, 0x26, 0x47, 0x16, 0xef, 0xde,
0x96, 0x1c, 0x0d, 0xb4, 0xa7, 0xed,
0x70, 0x31, 0x40, 0xfd, 0x6d, 0x86,
0x15, 0x7c, 0x9a, 0x51, 0x3f, 0xa5,
0xe2, 0xa5, 0xdc, 0x8e, 0x06, 0x6f,
//
// Data from a oyster card
0x37, 0x4b, 0xf4, 0x68, 0x60, 0x7f,
0xbf, 0xc8, 0xe3, 0x53, 0xaf, 0x63,
0x15, 0xca, 0xfd, 0x61, 0x59, 0xf6,
0x62, 0xef, 0xd8, 0x0a, 0xb7, 0x15,
0x98, 0x7a, 0x7f, 0x7f, 0x1a, 0x35,
0xc4, 0x10, 0x4f, 0xa3, 0xc5, 0x26,
0x4c, 0x96, 0x1f, 0x23, 0xe6, 0xbe,
0x67, 0x54, 0x69, 0x72, 0xbc, 0x69,
0xf4, 0xcd, 0x5d, 0x4c, 0x13, 0xff,
0x94, 0x41, 0x4c, 0x1a, 0x07, 0xdc,
0x16, 0x55, 0x1d, 0x52, 0xfd, 0x20,
0x9c, 0xb2, 0x90, 0x28, 0x2f, 0x7d,
0x77, 0xa8, 0x41, 0x70, 0xb5, 0x74,
0xed, 0x64, 0x6c, 0x83, 0xa4, 0xf3,
0xe7, 0x03, 0x58, 0x9d, 0xb5, 0x0b,
0x51, 0x3c, 0x85, 0xd0, 0x6c, 0xde,
0x95, 0x09, 0x3f, 0x0b, 0x2e, 0x22,
0x54, 0x3b, 0x01, 0xb2, 0x7a, 0x95,
0xc6, 0xd3, 0x75, 0xb9, 0x99, 0x72,
0xee, 0x4c, 0xc5, 0x72, 0xb4, 0x0e,
0x51, 0x06, 0xca, 0x7e, 0x4a, 0x69,
0xc9, 0x6b, 0xd1, 0xce, 0x60, 0x7f,
0x16, 0x7a, 0x1b, 0xe1, 0x02, 0xe0,
0xa8, 0xd0, 0xd8, 0x50, 0xa6, 0x06,
0xa2, 0xab, 0xb6, 0x93, 0xce, 0x34,
0x7b, 0x29, 0x6c, 0x40, 0xc4, 0x86,
0x91, 0xf9, 0x3a, 0x55, 0x64, 0xc9,
0xe1, 0x06, 0x23, 0xe7, 0xa0, 0x16,
0xb7, 0x25, 0xf9, 0xcb, 0xf1, 0x83,
//
// Data from FDi tag
0x88, 0x29, 0xda, 0x9d, 0xaf, 0x76,
//
// Data from GitHub issue
0x0A, 0x79, 0x32, 0xDC, 0x7E, 0x65,
0x11, 0x42, 0x8B, 0x5B, 0xCE, 0x06,
0x11, 0x42, 0x8B, 0x5B, 0xCE, 0x07,
0x11, 0x42, 0x8B, 0x5B, 0xCE, 0x08,
0x11, 0x42, 0x8B, 0x5B, 0xCE, 0x09,
0x11, 0x42, 0x8B, 0x5B, 0xCE, 0x0A,
0x11, 0x42, 0x8B, 0x5B, 0xCE, 0x0F,
0x18, 0x97, 0x1D, 0x89, 0x34, 0x94,
0x25, 0xD6, 0x00, 0x50, 0xBF, 0x6E,
0x3F, 0xA7, 0x21, 0x7E, 0xC5, 0x75,
0x44, 0xF0, 0xB5, 0xFB, 0xE3, 0x44,
0x7B, 0x29, 0x6F, 0x35, 0x3C, 0x6B,
0x85, 0x53, 0x26, 0x3F, 0x4F, 0xF0,
0x8E, 0x5D, 0x33, 0xA6, 0xED, 0x51,
0x9F, 0x42, 0x97, 0x1E, 0x83, 0x22,
0xC6, 0x20, 0x31, 0x8E, 0xF1, 0x79,
0xD4, 0xFE, 0x03, 0xCE, 0x5B, 0x06,
0xD4, 0xFE, 0x03, 0xCE, 0x5B, 0x07,
0xD4, 0xFE, 0x03, 0xCE, 0x5B, 0x08,
0xD4, 0xFE, 0x03, 0xCE, 0x5B, 0x09,
0xD4, 0xFE, 0x03, 0xCE, 0x5B, 0x0A,
0xD4, 0xFE, 0x03, 0xCE, 0x5B, 0x0F,
0xE2, 0x41, 0xE8, 0xAF, 0xCB, 0xAF,
//
// Data from forum post
0x12, 0x3F, 0x88, 0x88, 0xF3, 0x22,
0x05, 0x09, 0x08, 0x08, 0x00, 0x08,
//
// Data from hoist
0x4f, 0x9f, 0x59, 0xc9, 0xc8, 0x75,
//
// Data from pastebin
0x66, 0xf3, 0xed, 0x00, 0xfe, 0xd7,
0xf7, 0xa3, 0x97, 0x53, 0xd0, 0x18,
//
// Data from https://pastebin.com/Z7pEeZif
0x38, 0x6B, 0x4D, 0x63, 0x4A, 0x65,
0x66, 0x6E, 0x56, 0x4F, 0x4A, 0x44,
0x56, 0x47, 0x77, 0x31, 0x52, 0x76,
0x47, 0x62, 0x42, 0x30, 0x4C, 0x53,
0x6A, 0x69, 0x6B, 0x64, 0x66, 0x31,
0x4D, 0x32, 0x48, 0x73, 0x51, 0x31,
0x42, 0x5A, 0x73, 0x48, 0x41, 0x66,
0x57, 0x78, 0x4A, 0x53, 0x30, 0x69,
0x34, 0x55, 0x47, 0x51, 0x4B, 0x4D,
0x4C, 0x6B, 0x69, 0x72, 0x34, 0x61,
0x4E, 0x41, 0x75, 0x62, 0x36, 0x70,
0x4D, 0x50, 0x76, 0x65, 0x6D, 0x58,
0x68, 0x6A, 0x73, 0x6A, 0x35, 0x6E,
0x48, 0x4A, 0x57, 0x69, 0x6F, 0x4A,
0x6F, 0x4B, 0x6D, 0x64, 0x41, 0x78,
0x74, 0x4E, 0x32, 0x6B, 0x34, 0x41,
0x70, 0x56, 0x46, 0x50, 0x58, 0x4F,
0x58, 0x4F, 0x66, 0x32, 0x68, 0x77,
0x6D, 0x4E, 0x33, 0x4B, 0x6C, 0x48,
0x6A, 0x67, 0x6C, 0x31, 0x51, 0x42,
0x77, 0x49, 0x4C, 0x52, 0x63, 0x39,
0x62, 0x30, 0x55, 0x72, 0x45, 0x56,
0x35, 0x6D, 0x46, 0x47, 0x43, 0x48,
0x4E, 0x32, 0x33, 0x6C, 0x6E, 0x38,
0x57, 0x73, 0x4F, 0x6F, 0x69, 0x74,
0x43, 0x6A, 0x46, 0x58, 0x75, 0x52,
0x55, 0x44, 0x56, 0x4E, 0x6E, 0x67,
0x6F, 0x50, 0x6F, 0x49, 0x33, 0x53,
0x31, 0x64, 0x62, 0x41, 0x68, 0x6C,
0x77, 0x64, 0x6B, 0x63, 0x36, 0x57,
//
// Data from TransPert
0x20, 0x31, 0xd1, 0xe5, 0x7a, 0x3b,
0x68, 0xd3, 0xf7, 0x30, 0x7c, 0x89,
0x53, 0xc1, 0x1f, 0x90, 0x82, 0x2a,
0x91, 0x89, 0x44, 0x9e, 0xa2, 0x4e,
0x56, 0x8c, 0x90, 0x83, 0xf7, 0x1c,
//
// data from Github
0x41, 0x0b, 0x9b, 0x40, 0xb8, 0x72,
0x2c, 0xb1, 0xa9, 0x00, 0x71, 0xc8,
//
// data from
0x86, 0x97, 0x38, 0x9A, 0xCA, 0x26,
0x1A, 0xB2, 0x3C, 0xD4, 0x5E, 0xF6,
0x01, 0x38, 0x89, 0x34, 0x38, 0x91,
//
//
0x00, 0x00, 0x00, 0x00, 0x18, 0xde,
0x16, 0xdd, 0xcb, 0x6b, 0x3f, 0x24,
//
// Data from https://pastebin.com/vwDRZW7d
0xEC, 0x0A, 0x9B, 0x1A, 0x9E, 0x06, // Vingcard Mifare 4k Staff card
0x6C, 0x94, 0xE1, 0xCE, 0xD0, 0x26, // Vingcard Mifare 4k Staff card
0x0F, 0x23, 0x06, 0x95, 0x92, 0x3F, // Vingcard Mifare 4k Staff card
0x00, 0x00, 0x01, 0x4B, 0x5C, 0x31, // Vingcard Mifare 4k Staff card
//
0xBE, 0xDB, 0x60, 0x4C, 0xC9, 0xD1,
0xB8, 0xA1, 0xF6, 0x13, 0xCF, 0x3D,
0xB5, 0x78, 0xF3, 0x8A, 0x5C, 0x61,
0xAD, 0x4F, 0xB3, 0x33, 0x88, 0xBF,
0x69, 0xFB, 0x7B, 0x7C, 0xD8, 0xEE,
0x2A, 0x6D, 0x92, 0x05, 0xE7, 0xCA,
0x2a, 0x2c, 0x13, 0xcc, 0x24, 0x2a,
0x27, 0xFB, 0xC8, 0x6A, 0x00, 0xD0,
0x01, 0xFA, 0x3F, 0xC6, 0x83, 0x49,
//
0x6D, 0x44, 0xB5, 0xAA, 0xF4, 0x64, // Smart Rider. Western Australian Public Transport Cards
0x17, 0x17, 0xE3, 0x4A, 0x7A, 0x8A, // Smart Rider. Western Australian Public Transport Cards
//
0x6B, 0x65, 0x79, 0x73, 0x74, 0x72, // RFIDeas
//
0x48, 0x49, 0x44, 0x20, 0x49, 0x53, // HID MIFARE Classic 1k Key
0x20, 0x47, 0x52, 0x45, 0x41, 0x54, // HID MIFARE Classic 1k Key
0x3B, 0x7E, 0x4F, 0xD5, 0x75, 0xAD, // HID MIFARE SO
0x11, 0x49, 0x6F, 0x97, 0x75, 0x2A, // HID MIFARE SO
//
0x41, 0x5A, 0x54, 0x45, 0x4B, 0x4D, // Luxeo/Aztek cashless vending
//
0x32, 0x19, 0x58, 0x04, 0x23, 0x33, // BQT
//
0x16, 0x0A, 0x91, 0xD2, 0x9A, 0x9C, // Aperio KEY_A Sector 1, 12, 13, 14, 15 Data Start 0 Length 48
//
0xb7, 0xbf, 0x0c, 0x13, 0x06, 0x6e, // Gallagher
//
// Boston, MA, USA Transit - MBTA Charlie Card
0x30, 0x60, 0x20, 0x6f, 0x5b, 0x0a, // charlie
0x5e, 0xc3, 0x9b, 0x02, 0x2f, 0x2b, // charlie
0x3a, 0x09, 0x59, 0x4c, 0x85, 0x87, // charlie
0xf1, 0xb9, 0xf5, 0x66, 0x9c, 0xc8, // charlie
0xf6, 0x62, 0x24, 0x8e, 0x7e, 0x89, // charlie
0x62, 0x38, 0x7b, 0x8d, 0x25, 0x0d, // charlie
0xf2, 0x38, 0xd7, 0x8f, 0xf4, 0x8f, // charlie
0x9d, 0xc2, 0x82, 0xd4, 0x62, 0x17, // charlie
0xaf, 0xd0, 0xba, 0x94, 0xd6, 0x24, // charlie
0x92, 0xee, 0x4d, 0xc8, 0x71, 0x91, // charlie
0xb3, 0x5a, 0x0e, 0x4a, 0xcc, 0x09, // charlie
0x75, 0x6e, 0xf5, 0x5e, 0x25, 0x07, // charlie
0x44, 0x7a, 0xb7, 0xfd, 0x5a, 0x6b, // charlie
0x93, 0x2b, 0x9c, 0xb7, 0x30, 0xef, // charlie
0x1f, 0x1a, 0x0a, 0x11, 0x1b, 0x5b, // charlie
0xad, 0x9e, 0x0a, 0x1c, 0xa2, 0xf7, // charlie
0xd5, 0x80, 0x23, 0xba, 0x2b, 0xdc, // charlie
0x62, 0xce, 0xd4, 0x2a, 0x6d, 0x87, // charlie
0x25, 0x48, 0xa4, 0x43, 0xdf, 0x28, // charlie
0x2e, 0xd3, 0xb1, 0x5e, 0x7c, 0x0f, // charlie
//
// Data from forum
0x6a, 0x19, 0x87, 0xc4, 0x0a, 0x21,
0x7f, 0x33, 0x62, 0x5b, 0xc1, 0x29,
//
0x60, 0x01, 0x2e, 0x9b, 0xa3, 0xfa,
//
0xde, 0x1f, 0xcb, 0xec, 0x76, 0x4b,
// Data from https://pastebin.com/Kz8xp4ev
0x2a, 0xa0, 0x5e, 0xd1, 0x85, 0x6f,
0x73, 0x06, 0x8f, 0x11, 0x8c, 0x13,
0x2b, 0x7f, 0x32, 0x53, 0xfa, 0xc5,
0xea, 0xac, 0x88, 0xe5, 0xdc, 0x99,
0xae, 0x3d, 0x65, 0xa3, 0xda, 0xd4,
0xa7, 0x3f, 0x5d, 0xc1, 0xd3, 0x33,
0xa8, 0x26, 0x07, 0xb0, 0x1c, 0x0d,
0x29, 0x10, 0x98, 0x9b, 0x68, 0x80,
0x0f, 0x1c, 0x63, 0x01, 0x3d, 0xba,
0xfb, 0xf2, 0x25, 0xdc, 0x5d, 0x58,
//
// Data https://pastebin.com/BEm6bdAE
// vingcard.txt
0x47, 0x08, 0x11, 0x1c, 0x86, 0x04,
0x3d, 0x50, 0xd9, 0x02, 0xea, 0x48,
0x96, 0xa3, 0x01, 0xbc, 0xe2, 0x67,
0x67, 0x00, 0xf1, 0x0f, 0xec, 0x09,
0x7a, 0x09, 0xcc, 0x1d, 0xb7, 0x0a,
0x56, 0x0f, 0x7c, 0xff, 0x2d, 0x81,
0x66, 0xb3, 0x1e, 0x64, 0xca, 0x4b,
0x9e, 0x53, 0x49, 0x1f, 0x68, 0x5b,
0x3a, 0x09, 0x91, 0x1d, 0x86, 0x0c,
0x8a, 0x03, 0x69, 0x20, 0xac, 0x0c,
0x36, 0x1f, 0x69, 0xd2, 0xc4, 0x62,
0xd9, 0xbc, 0xde, 0x7f, 0xc4, 0x89,
0x0c, 0x03, 0xa7, 0x20, 0xf2, 0x08,
0x60, 0x18, 0x52, 0x2f, 0xac, 0x02,
//
// Data from https://pastebin.com/4t2yFMgt
// Mifare technische Universität Graz TUG
0xD5, 0x86, 0x60, 0xD1, 0xAC, 0xDE,
0x50, 0xA1, 0x13, 0x81, 0x50, 0x2C,
0xC0, 0x1F, 0xC8, 0x22, 0xC6, 0xE5,
0x08, 0x54, 0xBF, 0x31, 0x11, 0x1E,
// More keys:
0x8a, 0x19, 0xd4, 0x0c, 0xf2, 0xb5,
0xae, 0x85, 0x87, 0x10, 0x86, 0x40
};
#endif
