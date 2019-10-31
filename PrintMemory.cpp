#include "PrintMemory.hpp"

template<typename __Type>
static bool ProbeForRead(const void* p, void* out) {
    __try {
        *reinterpret_cast<__Type*>(out) = *reinterpret_cast<const __Type*>(p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

//
//  Print memory data in [lpMemBegin, lpMemEnd) at least
//  If `base` is not nullptr, print address as offset. Otherwise, as absolute address.
//  NOTICE:
//      `base` must >= `from`
//
void PrintMemory(const void* lpMemBegin, const void* lpMemEnd, const void* lpBase) noexcept {
    auto pbBegin = reinterpret_cast<const uint8_t*>(lpMemBegin);
    auto pbEnd = reinterpret_cast<const uint8_t*>(lpMemEnd);
    auto pbBase = reinterpret_cast<const uint8_t*>(lpBase);

    if (pbBegin >= pbEnd)
        return;

    while (reinterpret_cast<uintptr_t>(pbBegin) % 16)
        pbBegin--;

    while (reinterpret_cast<uintptr_t>(pbEnd) % 16)
        pbEnd++;

    while (pbBegin < pbEnd) {
        uint16_t Values[16] = {};

        if (pbBase) {
            uintptr_t d = pbBegin >= lpBase ? pbBegin - pbBase : pbBase - pbBegin;
            if (pbBegin >= lpBase) {
                _tprintf_s(TEXT("+0x%.*zx  "), static_cast<int>(2 * sizeof(void*)), d);
            } else {
                _tprintf_s(TEXT("-0x%.*zx  "), static_cast<int>(2 * sizeof(void*)), d);
            }
        } else {
            _tprintf_s(TEXT("0x%.*zx  "), static_cast<int>(2 * sizeof(void*)), reinterpret_cast<uintptr_t>(pbBegin));
        }

        for (int i = 0; i < 16; ++i) {
            if (pbBegin + i < lpMemBegin || pbBegin + i >= lpMemEnd) {
                _tprintf_s(TEXT("   "));
                Values[i] = 0xfffe;
            } else if (ProbeForRead<uint8_t>(pbBegin + i, Values + i)) {
                _tprintf_s(TEXT("%02x "), Values[i]);
            } else {
                _tprintf_s(TEXT("?? "));
                Values[i] = 0xffff;
            }
        }

        _tprintf_s(TEXT(" "));

        for (int i = 0; i < 16; ++i) {  // NOLINT
            if (0x20 <= Values[i] && Values[i] < 0x7f) {
                _tprintf_s(TEXT("%c"), Values[i]);
            } else if (Values[i] == 0xfffe) {
                _tprintf_s(TEXT(" "));
            } else {
                _tprintf_s(TEXT("."));
            }
        }

        _tprintf_s(TEXT("\n"));

        pbBegin += 0x10;
    }
}

void PrintMemory(const void* lpMem, size_t cbMem, const void* lpBase) noexcept {
    PrintMemory(lpMem, reinterpret_cast<const uint8_t*>(lpMem) + cbMem, lpBase);
}
