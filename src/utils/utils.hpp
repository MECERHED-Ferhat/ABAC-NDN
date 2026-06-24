#ifndef MACPABE_UTILS_HPP
#define MACPABE_UTILS_HPP
#include <pbc/pbc.h>
#include <string>
// #include "Global.h"
#ifdef ESP32
#include "Arduino.h"
#include "esputils.h"
#else
#include <fstream>
#include <iostream>
#endif // ESP32

inline void hexToBytes(const std::string &hex, unsigned char *output,
                       int &length) {
    length = hex.length() / 2;

    for (size_t i = 0; i < length; i++) {
        std::string byteString = hex.substr(i * 2, 2);
        output[i] =
            static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
    }
}

inline std::string bytesToHex(const unsigned char *data, size_t length) {
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string hex_str;
    hex_str.reserve(length * 2);

    for (size_t i = 0; i < length; ++i) {
        hex_str.push_back(hex_digits[(data[i] >> 4) & 0x0F]); // upper 4 bits
        hex_str.push_back(hex_digits[data[i] & 0x0F]);        // lower 4 bits
    }

    return hex_str;
}

#ifndef ESP32
inline std::string readFile(const char *filename_params) {
    std::string param_buffer;
    // For x86, use std::ifstream
    std::ifstream file(filename_params);
    if (!file.is_open()) {
        log_e("Failed to open pairing parameters file %s", filename_params);
        return 0;
    }
    std::string line;
    while (std::getline(file, line)) {
        param_buffer += line + "\n";
    }
    file.close();
    return param_buffer;
}
#endif // ESP32

inline std::pair<std::string, std::string> splitLine(const std::string &line) {
    size_t pos = line.find(':');
    if (pos == std::string::npos)
        return {"", ""};
    std::string key = line.substr(0, pos);
    std::string value = line.substr(pos + 1);
    key.erase(0, key.find_first_not_of(" \t\n\r"));
    key.erase(key.find_last_not_of(" \t\n\r") + 1);
    value.erase(0, value.find_first_not_of(" \t\n\r"));
    value.erase(value.find_last_not_of(" \t\n\r") + 1);
    return {key, value};
}

inline int init_pbc_params_from_file(pairing_t pairing,
                                     const char *filename_params,
                                     element_t generator,
                                     const char *filename_generator = nullptr) {
    std::string param_buffer;
#ifdef ESP32
    if (!read_spiffs_file(filename_params, param_buffer)) {
        log_e("Failed to read pairing parameters");
        return 0;
    }
#else
    param_buffer = readFile(filename_params);
#endif // ESP32
    pairing_init_set_str(pairing, param_buffer.c_str());

    if (!pairing_is_symmetric(pairing)) {
        log_e("Error: Pairing must be symmetric");
        return 0;
    }

    element_init_G1(generator, pairing);
    if (filename_generator == nullptr) {
        log_d("Generator filename is null, generating random generator");
        element_random(generator);
        return 1;
    }

    std::string generator_buffer;
#ifdef ESP32
    if (!read_spiffs_file(filename_generator, generator_buffer)) {
        log_e("Failed to read generator");
        return 0;
    }
#else
    generator_buffer = readFile(filename_generator);
#endif // ESP32

    element_from_bytes(generator, (unsigned char *)generator_buffer.c_str());

    return 1;
}

inline void init_global_parameters(GlobalParameter &GP,
                                   const char *filename_params,
                                   const char *filename_generator = nullptr) {
    if (!init_pbc_params_from_file(GP.e, filename_params, GP.g,
                                   filename_generator)) {
        log_e("Failed to read global parameters");
        pbc_die("pairing error");
    }

    element_t e_G1, e_GT, e_Zr;
    element_init_G1(e_G1, GP.e);
    element_init_GT(e_GT, GP.e);
    element_init_Zr(e_Zr, GP.e);

    BUFFER_SIZE["G1"] = element_length_in_bytes(e_G1);
    BUFFER_SIZE["GT"] = element_length_in_bytes(e_GT);
    BUFFER_SIZE["ZN"] = element_length_in_bytes(e_Zr);

    // log_d("Buffer sizes: G1=%d, GT=%d, ZN=%d", BUFFER_SIZE["G1"],
    //       BUFFER_SIZE["GT"], BUFFER_SIZE["ZN"]);

    element_clear(e_G1);
    element_clear(e_GT);
    element_clear(e_Zr);

    log_d("init GP done");

    // element_printf("Generator: %B\n", GP.g);
}

#endif // MACPABE_UTILS_HPP