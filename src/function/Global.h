#ifndef GLOBAL_H
#define GLOBAL_H

#ifndef ESP32
#define log_d(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define log_i(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define log_e(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define log_w(fmt, ...) printf("[WARNING] " fmt "\n", ##__VA_ARGS__)
#define log_v(fmt, ...) printf("[VERBOSE] " fmt "\n", ##__VA_ARGS__)
#define checkMemory(location) MemCheckResult::OK
#define String std::string
#endif

#include <iostream>
#include <pbc/pbc.h>
#include <string_view>
#include <unordered_map>
#include <vector>

#define MA_CP_ABE_DEFAULT_KEYLENGTH 16U

extern std::unordered_map<std::string, int> BUFFER_SIZE;

// Type definition for attributes
using attribute_t = std::string;

/// @brief Public Key type: pairing result (GT element) and G1 element
struct pk_components_s {
    uint32_t version;
    unsigned char *
        egg_pow_alpha_delta; // pairing result (GT element) or a_i if master key
    unsigned char *g_pow_y_delta; // G1 element or y_i if master key
};

/// @brief Raw Public Key type: pairing result (GT element) and G1 element
struct raw_pk_components_s {
    unsigned char
        *egg_pow_alpha;     // pairing result (GT element) or a_i if master key
    unsigned char *g_pow_y; // G1 element or y_i if master key
};

/// @brief Master Key type: pairing result (GT element) and G1 element
struct mk_components_s {
    unsigned char *alpha; // pairing result (GT element) or a_i if master key
    unsigned char *y;     // G1 element or y_i if master key
};

/// @brief Client Update type: gamma and random factor
struct client_update_s {
    unsigned char *gamma;         // gamma value for update
    unsigned char *random_factor; // random factor for update
};

/// @brief Master key or Public Key type: per attribute a vector of keys
typedef std::unordered_map<attribute_t, mk_components_s> master_key_map_t;

/// @brief Master key or Public Key type: per attribute a vector of keys
typedef std::unordered_map<attribute_t, pk_components_s> public_key_map_t;

/// @brief Master key or Public Key type: per attribute a vector of keys
typedef std::unordered_map<attribute_t, raw_pk_components_s> raw_pk_map_t;

/// @brief Type for reference map from attribute to authority
typedef std::unordered_map<attribute_t, std::string> auth_reference_t;

/// @brief Type for reference map from attribute to client key
typedef std::unordered_map<attribute_t, unsigned char *> client_key_map_t;

/// @brief Type for reference map from attribute to client update
typedef std::unordered_map<attribute_t,
                           std::unordered_map<uint32_t, client_update_s>>
    client_update_map_t;

/// @brief Stores the global parameters for the pairing-based cryptography
struct GlobalParameter {
    pairing_t e; ///< pairing object
    element_t g; ///< generator of G1
};

/**
 * @brief Default timeout for producers managed by the authority (in
 * milliseconds)
 */
constexpr uint32_t AUTHORITY_PRODUCER_DEFAULT_TIMEOUT_MS = 60000;

#endif // GLOBAL_H