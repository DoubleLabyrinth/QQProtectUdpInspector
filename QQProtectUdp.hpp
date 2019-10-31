#pragma once
#include <windows.h>
#include "TXCrypto.hpp"
#include "TXTeaCipher.hpp"

#pragma pack(push, 1)
struct QPUdpPacket {
    BYTE cBeginMagic;
    WORD wPacketSize;
    BYTE Unknown0;
    DWORD dwClientVer;
    WORD wCsCmdNo;
    BYTE cCcSubNo;
    WORD wSequence;
    DWORD dwUin;
    BYTE PCID[16];
    BYTE cOsType;
    BYTE cIsWow64;
    DWORD dwQQVersion0;
    WORD wQQVersion1;
    DWORD dwDrvVerMS;
    DWORD dwDrvVerLS;
    DWORD dwTSSafeEditDatFileVerMS;
    DWORD dwTSSafeEditDatFileVerLS;
    DWORD dwQQScanEngineDllFileVerMS;
    DWORD dwQQScanEngineDllFileVerLS;
    BYTE Unknown1;
    BYTE Payload[ANYSIZE_ARRAY];
};
#pragma pack(pop)

PCTSTR 
QPUdpPacketGetCodecName(
    const QPUdpPacket* lpPacket
);

void
QPUdpPacketPrintHeader(
    const QPUdpPacket* lpPacket
);

std::vector<uint8_t> 
QPUdpPacketGetPayload(
    const QPUdpPacket* lpPacket, 
    const std::vector<TXTeaCipher>& Ciphers, 
    size_t& LastCipherIdx,
    bool& IsDecrypted
);

void 
QPUdpPacketPrintPayload(
    const QPUdpPacket* lpPacket,
    const std::vector<uint8_t>& Payload,
    bool IsDecrypted
);

void QPUdpPacketModifyPayload(
    QPUdpPacket* lpPacket, 
    const TXTeaCipher& Cipher, 
    const std::vector<uint8_t>& Payload
);

