#ifndef AESWRAPPER_H
#define AESWRAPPER_H

#include "Global.h"

#ifndef ESP32
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#endif  // ESP32

// Symmetric scheme
class AESWrapper {
   public:
    AESWrapper(const unsigned char *key, size_t keyLength);

    std::string encryptAES(const std::string &plainText);
    std::string decryptAES(const std::string &cipherText);

   private:
    void generateIV(unsigned char *iv);
    std::string pad(const std::string &input);
    std::string unpad(const std::string &input);

#ifdef ESP32
    unsigned char key[MA_CP_ABE_DEFAULT_KEYLENGTH];
#else
    CryptoPP::byte key[MA_CP_ABE_DEFAULT_KEYLENGTH];
#endif  // ESP32
};

#endif  // AESWRAPPER_H