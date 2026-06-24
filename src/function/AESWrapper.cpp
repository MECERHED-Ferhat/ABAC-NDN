#include "AESWrapper.h"

#include <cstring>

#ifdef ESP32 // Clients
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#else // x86 Authority
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#endif // ESP32

#ifdef ESP32
AESWrapper::AESWrapper(const unsigned char *key, size_t keyLength) {
    if (keyLength != MA_CP_ABE_DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Key length must be 16 bytes");
    }
    std::memcpy(this->key, key, 16);
}

std::string AESWrapper::encrypt(const std::string &plainText) {
    // IV (Initialization Vector)
    unsigned char iv[16];
    generateIV(iv);

    // Pad plaintext to multiple of AES block size
    std::string paddedPlainText = pad(plainText);

    // Ciphertext output buffer
    std::vector<unsigned char> cipherText(paddedPlainText.size());

    // AES encryption context
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, MA_CP_ABE_DEFAULT_KEYLENGTH * 8);

    // Copy IV before encryption
    unsigned char ivCopy[16];
    std::memcpy(ivCopy, iv, sizeof(iv));

    // Encrypt in CBC mode
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedPlainText.size(), ivCopy,
                          (const unsigned char *)paddedPlainText.data(),
                          cipherText.data());

    mbedtls_aes_free(&aes);

    // Prepend IV to ciphertext
    std::string ivString(reinterpret_cast<char *>(iv), sizeof(iv));
    return ivString + std::string(cipherText.begin(), cipherText.end());
}

std::string AESWrapper::decrypt(const std::string &cipherText) {
    if (cipherText.size() < 16) {
        throw std::runtime_error("Invalid ciphertext size");
    }

    // Extract IV from the first 16 bytes
    unsigned char iv[16];
    std::memcpy(iv, cipherText.data(), 16);

    // Extract actual ciphertext
    std::string actualCipherText = cipherText.substr(16);
    std::vector<unsigned char> decrypted(actualCipherText.size());

    // AES decryption context
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);

    // Decrypt
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, actualCipherText.size(),
                          iv, (const unsigned char *)actualCipherText.data(),
                          decrypted.data());

    mbedtls_aes_free(&aes);

    // Remove padding
    return unpad(std::string(decrypted.begin(), decrypted.end()));
}

void AESWrapper::generateIV(unsigned char *iv) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr,
                          0);
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// PKCS7 padding for AES
std::string AESWrapper::pad(const std::string &input) {
    size_t padLen = 16 - (input.size() % 16);
    return input + std::string(padLen, (char)padLen);
}

// Unpad the PKCS7 padding
// This assumes the input is padded correctly and does not
// avoid the risk of padding oracle attacks. We should
// ensure that the input is valid before unpadding.
std::string AESWrapper::unpad(const std::string &input) {
    if (input.empty())
        return input;
    size_t padLen = static_cast<size_t>(input.back());
    return input.substr(0, input.size() - padLen);
}

#else
// Symmetric scheme

AESWrapper::AESWrapper(const unsigned char *key, size_t keyLength) {
    if (keyLength != MA_CP_ABE_DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Key length must be 16 bytes");
    }
    std::copy(key, key + keyLength, this->key);
}

std::string AESWrapper::encryptAES(const std::string &plainText) {
    std::string cipherText;
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv);

        CryptoPP::StringSource(
            plainText, true,
            new CryptoPP::StreamTransformationFilter(
                encryption, new CryptoPP::StringSink(cipherText)));
    } catch (const CryptoPP::Exception &e) {
        throw std::runtime_error(e.what());
    }

    std::string ivString(reinterpret_cast<char *>(iv), sizeof(iv));
    return ivString + cipherText; // Prepend IV to cipher text
}

std::string AESWrapper::decryptAES(const std::string &cipherText) {
    if (cipherText.size() < CryptoPP::AES::BLOCKSIZE) {
        throw std::runtime_error("Invalid cipher text size");
    }

    std::string plainText;

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    std::memcpy(iv, cipherText.data(), sizeof(iv));
    std::string actualCipherText = cipherText.substr(CryptoPP::AES::BLOCKSIZE);

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv);

        CryptoPP::StringSource(
            actualCipherText, true,
            new CryptoPP::StreamTransformationFilter(
                decryption, new CryptoPP::StringSink(plainText)));
    } catch (const CryptoPP::Exception &e) {
        throw std::runtime_error(e.what());
    }

    return plainText;
}

#endif