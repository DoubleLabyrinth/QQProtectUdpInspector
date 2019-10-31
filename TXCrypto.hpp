#pragma once
#include <stddef.h>
#include <stdint.h>
#include <memory.h>

#include <vector>
#include <stdexcept>

#include <NTSecAPI.h>
#pragma comment(lib, "Advapi32")

template<typename __CipherType>
std::vector<uint8_t> TXCryptoEncrypt(__CipherType&& Cipher, const std::vector<uint8_t>& Plaintext) {
    uint8_t Padding = 8 - (Plaintext.size() + 10) % 8;
    if (Padding == 8) {
        Padding = 0;
    }

    std::vector<uint8_t> Ciphertext((1 + Padding + 2 + Plaintext.size() + 7) / 8 * 8);

    RtlGenRandom(Ciphertext.data(), 1 + Padding + 2);
    Ciphertext[0] &= 0xF8;
    Ciphertext[0] |= Padding;

    memcpy(Ciphertext.data() + 1 + Padding + 2, Plaintext.data(), Plaintext.size());
    
    uint8_t Vector1[8] = {};
    uint8_t Vector2[8] = {};

    for (size_t i = 0; i < Ciphertext.size(); i += 8) {
        uint8_t NextVector1[8];

        for (size_t j = 0; j < 8; ++j) {
            Ciphertext[i + j] ^= Vector2[j];
            NextVector1[j] = Ciphertext[i + j];
        }

        Cipher.EncryptBlock(Ciphertext.data() + i);

        for (size_t j = 0; j < 8; ++j) {
            Ciphertext[i + j] ^= Vector1[j];
            Vector2[j] = Ciphertext[i + j];
        }

        memcpy(Vector1, NextVector1, 8);
    }

    return Ciphertext;
}

template<typename __CipherType>
std::vector<uint8_t> TXCryptoDecrypt(const __CipherType& Cipher, const std::vector<uint8_t>& Ciphertext) {
    if (Ciphertext.size() % 8 != 0) {
        throw std::length_error("The length of ciphertext is not a multiple of 8.");
    }

    if (Ciphertext.size() < 16) {
        throw std::length_error("The length of ciphertext is too short.");
    }

    uint8_t Header[8];
    memcpy(Header, Ciphertext.data(), 8);

    Cipher.DecryptBlock(Header);

    if (Ciphertext.size() < Header[0] % 8 + 10u) {
        throw std::runtime_error("Ciphertext is corrupted.");
    }

    size_t cbPlaintext = Ciphertext.size() - Header[0] % 8 - 10;

    uint8_t Vector1[8] = {};
    uint8_t Vector2[8] = {};

    std::vector<uint8_t> Text = Ciphertext;
    for (size_t i = 0; i < Text.size(); i += 8) {
        for (size_t j = 0; j < 8; ++j) {
            Text[i + j] ^= Vector1[j];
        }

        Cipher.DecryptBlock(Text.data() + i);

        memcpy(Vector1, Text.data() + i, 8);

        for (size_t j = 0; j < 8; ++j) {
            Text[i + j] ^= Vector2[j];
        }

        memcpy(Vector2, Ciphertext.data() + i, 8);
    }

    auto& Plaintext = Text;
    Plaintext.erase(Plaintext.begin(), Plaintext.begin() + 1 + Header[0] % 8 + 2);

    for (auto i = cbPlaintext; i < Plaintext.size(); ++i) {
        if (Plaintext[i] != 0) {
            throw std::runtime_error("Failed to decrypt.");
        }
    }

    Plaintext.resize(cbPlaintext);

    return Plaintext;
}


