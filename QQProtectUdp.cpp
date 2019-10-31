#include "QQProtectUdp.hpp"
#include "PrintMemory.hpp"
#include <tchar.h>
#include <stdio.h>
#include <system_error>

static std::vector<WORD> gs_TargetSeq;

PCTSTR QPUdpPacketGetCodecName(const QPUdpPacket* lpQPUdpPacket) {
    WORD wCsCmdNo = _byteswap_ushort(lpQPUdpPacket->wCsCmdNo);
    BYTE cCcSubNo = lpQPUdpPacket->cCcSubNo;
    if (wCsCmdNo == 1) {
        return TEXT("CCsIPSignatureCodec");
    } else if (wCsCmdNo == 2) {
        return TEXT("CCsSessionKeyCodec");
    } else if (wCsCmdNo == 0x0003) {
        return TEXT("CCsHelloCodec");
    } else if (wCsCmdNo == 0x0004) {
        return TEXT("CCsGetSig2Codec");
    } else if (wCsCmdNo == 0x0005) {
        return TEXT("CCsLogoutCodec");
    } else if (wCsCmdNo == 0x0006) {
        return TEXT("CCsReportCodec");
    } else if (wCsCmdNo == 0x0007) {
        return TEXT("CCsFetchConfig");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x01) {
        return TEXT("CCsIntChkStrategyCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x03) {
        return TEXT("CCsFetchIATCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x05) {
        return TEXT("CCsFetchMemChkCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x07) {
        return TEXT("CCsFetchMemSnapShotCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x09) {
        return TEXT("CCsFetchCharateristicCodeCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x13) {
        return TEXT("CCsFetchPluginIATCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x15) {
        return TEXT("CCsFetchPluginMemChkCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x17) {
        return TEXT("CCsFetchPluginMemSnapShotCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x22) {
        return TEXT("CCsFetchWinTextCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x23) {
        return TEXT("CCsReportIATCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x24) {
        return TEXT("CCsReportMemChkCodec");
    } else if (wCsCmdNo == 0x0008 && cCcSubNo == 0x25) {
        return TEXT("CCsReportMemSnapShotCodec");
    } else if (wCsCmdNo == 0x000b && cCcSubNo == 0x01) {
        return TEXT("CCsFetchWinTextCfgFileCodec");
    } else if (wCsCmdNo == 0x000b && cCcSubNo == 0x02) {
        return TEXT("CCsFetchWinTextCfgFileExCodec");
    } else if (wCsCmdNo == 0x000c && cCcSubNo == 0x01) {
        return TEXT("CCsFetchGlobalStrategyCodec");
    } else if (wCsCmdNo == 0x000c && cCcSubNo == 0x02) {
        return TEXT("CCsFetchDefenceStrategyCodec");
    } else if (wCsCmdNo == 0x000c && cCcSubNo == 0x03) {
        return TEXT("CCsFetchFileOperationStrategyCodec");
    } else if (wCsCmdNo == 0x000c && cCcSubNo == 0x04) {
        return TEXT("CCSWebQuickLoginWhiteListCodec");
    } else if (wCsCmdNo == 0x000d && cCcSubNo == 0x01) {
        return TEXT("CCsFetchHijackDllNameList");
    } else if (wCsCmdNo == 0x000d && cCcSubNo == 0x02) {
        return TEXT("CCsQueryDllNameListVersion");
    } else if (wCsCmdNo == 0x000e && cCcSubNo == 0x03) {
        return TEXT("CCsHijackInfoReport");
    } else if (wCsCmdNo == 0x000f && cCcSubNo == 0x01) {
        return TEXT("CCsUinReport");
    } else if (wCsCmdNo == 0x0011 && cCcSubNo == 0x10) {
        return TEXT("CCsPullTacticFileCodec");
    } else if (wCsCmdNo == 0x0012) {
        return TEXT("CCsGetSignedFileInfoCodec");
    } else if (wCsCmdNo == 0x0014 && cCcSubNo == 0x06) {
        return TEXT("CCsSvrCloudCodec");
    } else if (wCsCmdNo == 0x0016 && cCcSubNo == 0x00) {
        return TEXT("CCsFetchQRLoginTip");
    } else if (wCsCmdNo == 0x0017 && cCcSubNo == 0x01) {
        return TEXT("CCsFetchQRLoginCfg");
    } else if (wCsCmdNo == 0x0018) {
        return TEXT("CCsMSWIN10Report");
    } else if (wCsCmdNo == 0x001a && cCcSubNo == 0x01) {
        return TEXT("CCsHTTP2CSReport");
    } else if (wCsCmdNo == 0x001b && cCcSubNo == 0x01) {
        return TEXT("CCsHello2Codec");
    } else if (wCsCmdNo == 0x001c && cCcSubNo == 0x02) {
        return TEXT("CCSPushReply");
    } else if (wCsCmdNo == 0x001d && cCcSubNo == 0x01) {
        return TEXT("CCSPushRequest");
    } else if (wCsCmdNo == 0x002d && cCcSubNo == 0x01) {
        return TEXT("CCSWebPtloginCodec");
    } else {
        return TEXT("null");
    }
}

void QPUdpPacketPrintHeader(const QPUdpPacket* lpQPUdpPacket) {
    static bool ConsoleScreenOriginalInfoInit = false;
    static CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenOriginalInfo = {};

    if (ConsoleScreenOriginalInfoInit == false) {
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ConsoleScreenOriginalInfo) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        ConsoleScreenOriginalInfoInit = true;
    }

    if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), ConsoleScreenOriginalInfo.wAttributes & 0xfff0u | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)) {
        auto err = GetLastError();
        throw std::system_error(err, std::system_category());
    }

    _tprintf_s(TEXT("[*] PacketSize:            0x%.4x\n"), _byteswap_ushort(lpQPUdpPacket->wPacketSize));
    _tprintf_s(TEXT("[*] Client Verion:         %d.%d.%d.%d\n"),
        (lpQPUdpPacket->dwClientVer >> 0u) & 0xffu,
        (lpQPUdpPacket->dwClientVer >> 8u) & 0xffu,
        (lpQPUdpPacket->dwClientVer >> 16u) & 0xffu,
        (lpQPUdpPacket->dwClientVer >> 24u) & 0xffu
    );
    _tprintf_s(TEXT("[*] wCsCmdNo, cCcSubNo:    0x%.4x, 0x%.2x (%s)\n"),
        _byteswap_ushort(lpQPUdpPacket->wCsCmdNo), lpQPUdpPacket->cCcSubNo,
        QPUdpPacketGetCodecName(lpQPUdpPacket)
    );
    _tprintf_s(TEXT("[*] Sequence:              0x%.4x\n"), _byteswap_ushort(lpQPUdpPacket->wSequence));
    _tprintf_s(TEXT("[*] Uin:                   0x%.8x\n"), _byteswap_ulong(lpQPUdpPacket->dwUin));
    _tprintf_s(TEXT("[*] PCID:                  %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n"),
        lpQPUdpPacket->PCID[0],
        lpQPUdpPacket->PCID[1],
        lpQPUdpPacket->PCID[2],
        lpQPUdpPacket->PCID[3],
        lpQPUdpPacket->PCID[4],
        lpQPUdpPacket->PCID[5],
        lpQPUdpPacket->PCID[6],
        lpQPUdpPacket->PCID[7],
        lpQPUdpPacket->PCID[8],
        lpQPUdpPacket->PCID[9],
        lpQPUdpPacket->PCID[10],
        lpQPUdpPacket->PCID[11],
        lpQPUdpPacket->PCID[12],
        lpQPUdpPacket->PCID[13],
        lpQPUdpPacket->PCID[14],
        lpQPUdpPacket->PCID[15]
    );
    _tprintf_s(TEXT("[*] OsType:                0x%.2x\n"), lpQPUdpPacket->cOsType);
    _tprintf_s(TEXT("[*] IsWow64:               0x%.2x\n"), lpQPUdpPacket->cIsWow64);

    if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), ConsoleScreenOriginalInfo.wAttributes)) {
        auto err = GetLastError();
        throw std::system_error(err, std::system_category());
    }
}

std::vector<uint8_t> QPUdpPacketGetPayload(const QPUdpPacket* lpQPUdpPacket, const std::vector<TXTeaCipher>& Ciphers, size_t& LastCipherIdx, bool& IsDecrypted) {
    if (_byteswap_ushort(lpQPUdpPacket->wCsCmdNo) == 1) {   // CCsIPSignatureCodec is not encrypted
        IsDecrypted = true;
        return std::vector<uint8_t>(
            lpQPUdpPacket->Payload, 
            lpQPUdpPacket->Payload + _byteswap_ushort(lpQPUdpPacket->wPacketSize) - sizeof(QPUdpPacket)
        );
    } else {
        std::vector<uint8_t> Payload{
            lpQPUdpPacket->Payload,
            lpQPUdpPacket->Payload + _byteswap_ushort(lpQPUdpPacket->wPacketSize) - sizeof(QPUdpPacket)
        };

        try {
            Payload = TXCryptoDecrypt(Ciphers[LastCipherIdx], Payload);
            IsDecrypted = true;
        } catch (...) {
            IsDecrypted = false;
        }

        for (size_t i = 0; IsDecrypted == false && i < Ciphers.size(); ++i) {
            if (i == LastCipherIdx)
                continue;

            try {
                Payload = TXCryptoDecrypt(Ciphers[i], Payload);
                LastCipherIdx = i;
                IsDecrypted = true;
            } catch (...) {
                IsDecrypted = false;
            }
        }

        return Payload;
    }
}

void QPUdpPacketPrintPayload(const QPUdpPacket* lpQPUdpPacket, const std::vector<uint8_t>& Payload, bool IsDecrypted) {
    static bool ConsoleScreenOriginalInfoInit = false;
    static CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenOriginalInfo = {};

    if (ConsoleScreenOriginalInfoInit == false) {
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ConsoleScreenOriginalInfo) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        ConsoleScreenOriginalInfoInit = true;
    }

    _tprintf_s(
        TEXT("[%c] Payload[%s]:\n"),
        IsDecrypted ? TEXT('+') : TEXT('-'),
        IsDecrypted ? TEXT("DECRYPTED") : TEXT("NOT DECRYPTED")
    );

    if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), ConsoleScreenOriginalInfo.wAttributes & 0xfff0u | (IsDecrypted ? FOREGROUND_GREEN : FOREGROUND_RED) | FOREGROUND_INTENSITY)) {
        auto err = GetLastError();
        throw std::system_error(err, std::system_category());
    }

    PrintMemory(Payload.data(), Payload.size(), Payload.data());

    if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), ConsoleScreenOriginalInfo.wAttributes)) {
        auto err = GetLastError();
        throw std::system_error(err, std::system_category());
    }

    if (IsDecrypted) {
        if (lpQPUdpPacket->wCsCmdNo == _byteswap_ushort(0x000b) && lpQPUdpPacket->cCcSubNo == 0x02) {
            if (*reinterpret_cast<const WORD*>(Payload.data() + 8) == _byteswap_ushort(2) &&
                *reinterpret_cast<const DWORD*>(Payload.data() + 10) == _byteswap_ulong(6) &&
                *reinterpret_cast<const DWORD*>(Payload.data() + 14) == _byteswap_ulong(7)) 
            {
                gs_TargetSeq.push_back(lpQPUdpPacket->wSequence);
            }
        }
    }
}
