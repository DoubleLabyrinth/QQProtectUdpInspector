#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <vector>
#include <system_error>
#include "ResourceWrapper.hpp"
#include "ResourceTraitsWin32.hpp"
#include "ResourceTraitsWinDivert.hpp"
#include "PrintMemory.hpp"
#include "QQProtectUdp.hpp"

auto g_Stop = false;
auto g_hWinDivert = ARL::ResourceWrapper<ARL::ResourceTraits::WinDivertHandle>();

#pragma warning(push)
#pragma warning(disable: 6262)
int _tmain(int argc, PTSTR argv[]) {
    try {
        if (SetConsoleCtrlHandler([](DWORD CtrlType) -> BOOL { g_Stop = true; g_hWinDivert.Release(); return TRUE; }, TRUE) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        g_hWinDivert.TakeOver(
            WinDivertOpen(
                "ip && (udp.SrcPort == 8000 || udp.DstPort == 8000) && udp.Payload[0] == 0x3e && udp.Payload[-1] == 0x68",
                WINDIVERT_LAYER_NETWORK,
                0,
                0
            )
        );
        if (g_hWinDivert.IsValid() == false) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        std::vector<TXTeaCipher> Ciphers;
        size_t LastCipherIdx = 0;

        Ciphers.emplace_back(TXTeaCipher{});
        Ciphers.emplace_back(TXTeaCipher{});
        Ciphers.emplace_back(TXTeaCipher{});
        Ciphers[0].SetKey({ 0x33, 0x55, 0x44, 0x5e, 0x55, 0x66, 0x6d, 0x42, 0x23, 0x67, 0x29, 0x25, 0x68, 0x31, 0x30, 0x5d });
        Ciphers[1].SetKey({ 0x77, 0x55, 0x36, 0x5e, 0x31, 0x59, 0x6d, 0x42, 0x23, 0x67, 0x29, 0x25, 0x68, 0x31, 0x30, 0x5d });
        Ciphers[2].SetKey({ 0x77, 0x45, 0x37, 0x5e, 0x33, 0x69, 0x6d, 0x67, 0x23, 0x69, 0x29, 0x25, 0x68, 0x31, 0x32, 0x5d });

        BYTE pbPacket[65536];
        UINT cbPacket = sizeof(pbPacket);
        while (g_Stop == false) {
            cbPacket = sizeof(pbPacket);

            WINDIVERT_ADDRESS WindivertAddress = {};
            PWINDIVERT_IPHDR Ipv4Header = NULL;
            PWINDIVERT_UDPHDR UdpHeader = NULL;
            PVOID lpUdpPayload = nullptr;
            UINT cbUdpPayload = 0;

            memset(pbPacket, 0, cbPacket);

            if (WinDivertRecv(g_hWinDivert, pbPacket, cbPacket, &cbPacket, &WindivertAddress)) {
                SYSTEMTIME CurrentTime;
                GetLocalTime(&CurrentTime);

                if (WinDivertHelperParsePacket(pbPacket, cbPacket, &Ipv4Header, nullptr, nullptr, nullptr, nullptr, nullptr, &UdpHeader, &lpUdpPayload, &cbUdpPayload, nullptr, nullptr)) {                                                   // when QPUdpPacket
                    auto lpQPUdpPacket = reinterpret_cast<QPUdpPacket*>(lpUdpPayload);
                    bool IsDecrypted;

                    std::vector<uint8_t> Payload = QPUdpPacketGetPayload(lpQPUdpPacket, Ciphers, LastCipherIdx, IsDecrypted);

                    _tprintf_s(
                        TEXT("[*] Time: %d/%d/%d %d:%d:%d.%d\n"),
                        CurrentTime.wYear, CurrentTime.wMonth, CurrentTime.wDay,
                        CurrentTime.wHour, CurrentTime.wMinute, CurrentTime.wSecond, CurrentTime.wMilliseconds
                    );

                    char SrcAddress[16] = {};
                    char DstAddress[16] = {};

                    WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(Ipv4Header->SrcAddr), SrcAddress, 16);
                    WinDivertHelperFormatIPv4Address(WinDivertHelperNtohl(Ipv4Header->DstAddr), DstAddress, 16);

                    TCHAR szSrcSocket[32] = {};
                    TCHAR szDstSocket[32] = {};

                    _stprintf_s(szSrcSocket, TEXT("%hs:%u"), SrcAddress, WinDivertHelperNtohs(UdpHeader->SrcPort));
                    _stprintf_s(szDstSocket, TEXT("%hs:%u"), DstAddress, WinDivertHelperNtohs(UdpHeader->DstPort));

                    if (WindivertAddress.Outbound) {
                        _tprintf_s(TEXT("[*] %-22s >>>>>>>>>>>>>>>> %22s\n"), szSrcSocket, szDstSocket);
                    } else {
                        _tprintf_s(TEXT("[*] %-22s <<<<<<<<<<<<<<<< %22s\n"), szDstSocket, szSrcSocket);
                    }

                    QPUdpPacketPrintHeader(lpQPUdpPacket);
                    QPUdpPacketPrintPayload(lpQPUdpPacket, Payload, IsDecrypted);

                    _tprintf_s(TEXT("\n"));

                    if (UdpHeader->SrcPort == _byteswap_ushort(8000) && IsDecrypted && _byteswap_ushort(lpQPUdpPacket->wCsCmdNo) == 2 && Payload[0] == 0 && Payload[1] == 0x10 && Payload.size() > 0x12) {
                        Ciphers.emplace_back(TXTeaCipher{});
                        Ciphers.back().SetKey(Payload.data() + 2, 16);
                        _tprintf_s(TEXT("[*] Add a session key.\n"));
                        _tprintf_s(TEXT("\n"));
                    }
                }

                if (WinDivertSend(g_hWinDivert, pbPacket, cbPacket, &cbPacket, &WindivertAddress) == FALSE) {
                    auto err = GetLastError();
                    throw std::system_error(err, std::system_category());
                }
            } else {
                auto err = GetLastError();
                if (err == ERROR_OPERATION_ABORTED) {
                    Sleep(500);
                    break;
                } else {
                    throw std::system_error(err, std::system_category());
                }
            }
        }

        return 0;
    } catch (std::exception& e) {
        _tprintf_s(TEXT("[-] %hs\n"), e.what());
        return -1;
    }
}
#pragma warning(pop)
