#pragma once
#include <windows.h>
#include <WinDNS.h>

#pragma comment(lib, "Dnsapi")

namespace ARL::ResourceTraits {

    struct WinDnsRecordListW {
        using HandleType = PDNS_RECORDW;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(HandleType Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(HandleType Handle) noexcept {
            DnsRecordListFree(Handle, DnsFreeRecordList);
        }
    };

}

