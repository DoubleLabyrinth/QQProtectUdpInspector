#pragma once
#include <windivert.h>
#include <system_error>

#pragma comment(lib, "WinDivert")

namespace ARL::ResourceTraits {

    struct WinDivertHandle {
        using HandleType = HANDLE;

        static inline const HandleType InvalidValue = INVALID_HANDLE_VALUE;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            if (WinDivertClose(Handle) == FALSE) {
                auto err = GetLastError();
                throw std::system_error(err, std::system_category());
            }
        }
    };

}
