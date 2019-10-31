#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <windows.h>
#include <initializer_list>
#include <stdexcept>

class TXTeaCipher {
private:

    uint32_t m_Key[4];

public:

    TXTeaCipher() noexcept :
        m_Key{} {}

    void SetKey(const void* lpKey, size_t cbKey) {
        if (cbKey == sizeof(m_Key)) {
            memcpy(m_Key, lpKey, sizeof(m_Key));
            for (size_t i = 0; i < _countof(m_Key); ++i) {
                m_Key[i] = _byteswap_ulong(m_Key[i]);
            }
        } else {
            throw std::length_error("Incorrect key length.");
        }
    }

    void SetKey(const std::initializer_list<uint8_t>& Key) {
        if (Key.size() == sizeof(m_Key)) {
            std::copy(Key.begin(), Key.end(), reinterpret_cast<uint8_t(&)[16]>(m_Key));
            for (size_t i = 0; i < _countof(m_Key); ++i) {
                m_Key[i] = _byteswap_ulong(m_Key[i]);
            }
        } else {
            throw std::length_error("Incorrect key length.");
        }
    }

    size_t EncryptBlock(void* lpPlaintext) const noexcept {
        uint32_t block[2];

        memcpy(block, lpPlaintext, sizeof(block));
        block[0] = _byteswap_ulong(block[0]);
        block[1] = _byteswap_ulong(block[1]);

        uint32_t sum = 0;
        for (size_t i = 0; i < 32; ++i) {
            sum += 0x57E89147;
            block[0] += (sum + block[1]) ^ (m_Key[0] + 16 * block[1]) ^ (m_Key[1] + (block[1] >> 5));
            block[1] += (sum + block[0]) ^ (m_Key[2] + 16 * block[0]) ^ (m_Key[3] + (block[0] >> 5));
        }

        block[0] = _byteswap_ulong(block[0]);
        block[1] = _byteswap_ulong(block[1]);
        memcpy(lpPlaintext, block, sizeof(block));

        return sizeof(block);
    }

    size_t DecryptBlock(void* lpCiphertext) const noexcept {
        uint32_t block[2];

        memcpy(block, lpCiphertext, sizeof(block));
        block[0] = _byteswap_ulong(block[0]);
        block[1] = _byteswap_ulong(block[1]);

        uint32_t sum = 0xFD1228E0;
        for (size_t i = 0; i < 32; ++i) {
            block[1] -= (sum + block[0]) ^ (m_Key[2] + 16 * block[0]) ^ (m_Key[3] + (block[0] >> 5));
            block[0] -= (sum + block[1]) ^ (m_Key[0] + 16 * block[1]) ^ (m_Key[1] + (block[1] >> 5));
            sum -= 0x57E89147;
        }

        block[0] = _byteswap_ulong(block[0]);
        block[1] = _byteswap_ulong(block[1]);
        memcpy(lpCiphertext, block, sizeof(block));

        return sizeof(block);
    }

    void ClearKey() noexcept {
        SecureZeroMemory(m_Key, sizeof(m_Key));
    }

    ~TXTeaCipher() noexcept {
        ClearKey();
    }
};
