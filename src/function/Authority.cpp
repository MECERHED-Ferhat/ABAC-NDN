#include "Authority.h"
#include <filesystem>
#include "utils.hpp"
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <vector>

// Authority class

Authority::Authority(const std::string &gid) : GID(gid) {}


void Authority::SetupGlobalParameter(GlobalParameter &GP) {
    // Default
    const std::string param_file = "a.param";
    std::ifstream f(param_file, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Cannot open pairing parameter file: " + param_file);

    char pairing_param[1024];
    f.read(pairing_param, sizeof(pairing_param));
    size_t count = f.gcount();
    f.close();
    if (!count) pbc_die("input error");

    pairing_init_set_buf(GP.e, pairing_param, count);
    if (!pairing_is_symmetric(GP.e)) pbc_die("pairing must be symmetric");

    element_init_G1(GP.g, GP.e);

    element_random(GP.g);

    element_t e_G1, e_GT, e_Zr;
    element_init_G1(e_G1, GP.e);
    element_init_GT(e_GT, GP.e);
    element_init_Zr(e_Zr, GP.e);

    BUFFER_SIZE["G1"] = element_length_in_bytes(e_G1);
    BUFFER_SIZE["GT"] = element_length_in_bytes(e_GT);
    BUFFER_SIZE["ZN"] = element_length_in_bytes(e_Zr);

    element_clear(e_G1);
    element_clear(e_GT);
    element_clear(e_Zr);
}

void Authority::SetupGlobalParameterMedium(GlobalParameter &GP) {
    // Custom security level for Type A
    pbc_param_t param;

    int rbits = 224;
    int qbits = 1024;

    pbc_param_init_a_gen(param, rbits, qbits);
    pairing_init_pbc_param(GP.e, param);

    FILE *fp = fopen("a_112bit.param", "w");
    pbc_param_out_str(fp, param);
    fclose(fp);

    element_init_G1(GP.g, GP.e);

    element_random(GP.g);

    element_t e_G1, e_GT, e_Zr;
    element_init_G1(e_G1, GP.e);
    element_init_GT(e_GT, GP.e);
    element_init_Zr(e_Zr, GP.e);

    BUFFER_SIZE["G1"] = element_length_in_bytes(e_G1);
    BUFFER_SIZE["GT"] = element_length_in_bytes(e_GT);
    BUFFER_SIZE["ZN"] = element_length_in_bytes(e_Zr);

    element_clear(e_G1);
    element_clear(e_GT);
    element_clear(e_Zr);
}


void Authority::SetupGlobalParameterHigh(GlobalParameter &GP) {
    // Custom security level for Type A
    pbc_param_t param;

    int rbits = 256;
    int qbits = 1536;

    pbc_param_init_a_gen(param, rbits, qbits);
    pairing_init_pbc_param(GP.e, param);

    FILE *fp = fopen("a_128bit.param", "w");
    pbc_param_out_str(fp, param);
    fclose(fp);

    element_init_G1(GP.g, GP.e);

    element_random(GP.g);

    element_t e_G1, e_GT, e_Zr;
    element_init_G1(e_G1, GP.e);
    element_init_GT(e_GT, GP.e);
    element_init_Zr(e_Zr, GP.e);

    BUFFER_SIZE["G1"] = element_length_in_bytes(e_G1);
    BUFFER_SIZE["GT"] = element_length_in_bytes(e_GT);
    BUFFER_SIZE["ZN"] = element_length_in_bytes(e_Zr);

    element_clear(e_G1);
    element_clear(e_GT);
    element_clear(e_Zr);
}


void Authority::SetupAuthority(GlobalParameter &GP, Authority &auth, const std::vector<std::string> &attributes) {
    auth.GP = GP;
    for (const auto &attr : attributes) {
        auth.generateMasterKey(attr);
        auth.generatePublicKey(attr);
    }
}

void Authority::generateMasterKey(const attribute_t attr) {
    element_t alpha_i, y_i, delta_i;
    element_init_Zr(alpha_i, GP.e);
    element_init_Zr(y_i, GP.e);
    element_init_Zr(delta_i, GP.e);

    attributes.push_back(attr);

    // std::cout << std::endl
    //           << "*** Creation of MK for attribute: " << attr << std::endl;

    element_random(alpha_i);
    // element_printf("A = %B\n", alpha_i);
    element_random(y_i);
    // element_printf("Y = %B\n", y_i);
    element_set0(delta_i);

    mk_components_s mk_comps;
    mk_comps.alpha = new unsigned char[BUFFER_SIZE["ZN"]];
    mk_comps.y = new unsigned char[BUFFER_SIZE["ZN"]];

    element_to_bytes(mk_comps.alpha, alpha_i);
    element_to_bytes(mk_comps.y, y_i);

    master_keys[attr] = mk_comps;

    element_clear(alpha_i);
    element_clear(y_i);
    element_clear(delta_i);
}

/// @brief Generate "raw" public key for the given attribute
/// @param attr
/// @details This is the public key before the update. The delta value is not
/// included in this key. The update is done in the updatePublicKey function.
void Authority::generatePublicKey(const attribute_t attr) {
    element_t tmp_egg, tmp_egg_pow_alpha, tmp_g_pow_y, alpha_i, y_i;
    element_init_GT(tmp_egg, GP.e);
    element_init_GT(tmp_egg_pow_alpha, GP.e);
    element_init_G1(tmp_g_pow_y, GP.e);
    element_init_Zr(alpha_i, GP.e);
    element_init_Zr(y_i, GP.e);

    // std::cout << std::endl
    //           << "*** Creation of PK for attribute: " << attr << std::endl;

    element_from_bytes(alpha_i, master_keys[attr].alpha);
    element_from_bytes(y_i, master_keys[attr].y);

    element_pairing(tmp_egg, GP.g, GP.g);
    element_pow_zn(tmp_egg_pow_alpha, tmp_egg, alpha_i);
    element_pow_zn(tmp_g_pow_y, GP.g, y_i);

    raw_pk_components_s raw_pk_comps;
    raw_pk_comps.egg_pow_alpha = new unsigned char[BUFFER_SIZE["GT"]];
    raw_pk_comps.g_pow_y = new unsigned char[BUFFER_SIZE["G1"]];

    element_to_bytes(raw_pk_comps.egg_pow_alpha, tmp_egg_pow_alpha);
    element_to_bytes(raw_pk_comps.g_pow_y, tmp_g_pow_y);

    raw_public_keys[attr] = raw_pk_comps;

    element_clear(tmp_egg);
    element_clear(alpha_i);
    element_clear(y_i);

    element_clear(tmp_egg_pow_alpha);
    element_clear(tmp_g_pow_y);

    updatePublicKey(attr);
}

void Authority::storeRawPublicKeysDirectly(const attribute_t attr) {
    // free memory if a previous public key exists
    if (public_keys.find(attr) != public_keys.end()) {
        delete[] public_keys[attr].egg_pow_alpha_delta;
        delete[] public_keys[attr].g_pow_y_delta;
    }

    pk_components_s pk_comps;
    pk_comps.egg_pow_alpha_delta = new unsigned char[BUFFER_SIZE["GT"]];
    pk_comps.g_pow_y_delta = new unsigned char[BUFFER_SIZE["G1"]];
    pk_comps.version = 0; // no versioning 

    memcpy(pk_comps.egg_pow_alpha_delta, raw_public_keys[attr].egg_pow_alpha, BUFFER_SIZE["GT"]);
    memcpy(pk_comps.g_pow_y_delta, raw_public_keys[attr].g_pow_y, BUFFER_SIZE["G1"]);

    public_keys[attr] = pk_comps;
}

void Authority::updatePublicKey(const attribute_t attr) {
    element_t delta_i, rt_i;
    delta_list[attr] = new unsigned char[BUFFER_SIZE["ZN"]];
    t_list[attr] = new unsigned char[BUFFER_SIZE["ZN"]];

    element_init_Zr(delta_i, GP.e);
    element_init_Zr(rt_i, GP.e);

    element_random(delta_i);
    // element_printf("Delta = %B\n", delta_i);
    element_random(rt_i);
    // element_printf("T = %B\n", rt_i);

    element_to_bytes(delta_list[attr], delta_i);
    element_to_bytes(t_list[attr], rt_i);

    element_t raw_pk1, raw_pk2, tmp_raw_pk1_pow_delta,
        tmp_raw_pk2_pow_delta; // alpha_i, y_i;
    element_init_GT(raw_pk1, GP.e);
    element_init_G1(raw_pk2, GP.e);
    element_init_GT(tmp_raw_pk1_pow_delta, GP.e);
    element_init_G1(tmp_raw_pk2_pow_delta, GP.e);

    element_from_bytes(raw_pk1, raw_public_keys[attr].egg_pow_alpha);
    element_from_bytes(raw_pk2, raw_public_keys[attr].g_pow_y);

    element_pow_zn(tmp_raw_pk1_pow_delta, raw_pk1, delta_i);
    element_pow_zn(tmp_raw_pk2_pow_delta, raw_pk2, delta_i);

    pk_components_s pk_comps;
    pk_comps.egg_pow_alpha_delta = new unsigned char[BUFFER_SIZE["GT"]];
    pk_comps.g_pow_y_delta = new unsigned char[BUFFER_SIZE["G1"]];

    // Set the version - start at 0 if it's a new key or increment if
    // updating existing
    if (public_keys.find(attr) == public_keys.end()) {
        pk_comps.version = 0;
    } else {
        pk_comps.version = public_keys[attr].version + 1;
        // Free memory from previous version
        delete[] public_keys[attr].egg_pow_alpha_delta;
        delete[] public_keys[attr].g_pow_y_delta;
    }

    element_to_bytes(pk_comps.egg_pow_alpha_delta, tmp_raw_pk1_pow_delta);
    element_to_bytes(pk_comps.g_pow_y_delta, tmp_raw_pk2_pow_delta);

    //element_printf("PK[%s](egg^alpha.delta) = %B\n", attr.c_str(),
    //    tmp_raw_pk1_pow_delta);
    //element_printf("PK[%s](g^y.delta) = %B\n", attr.c_str(),
    //    tmp_raw_pk2_pow_delta);
    //printf("PK[%s] version = %u\n", attr.c_str(), pk_comps.version);

    public_keys[attr] = pk_comps;

    element_clear(raw_pk1);
    element_clear(raw_pk2);
    element_clear(tmp_raw_pk1_pow_delta);
    element_clear(tmp_raw_pk2_pow_delta);
    element_clear(delta_i);
    element_clear(rt_i);
}

std::string Authority::serializePublicKey(const attribute_t &attr) {
    std::ostringstream oss;

    if (public_keys.find(attr) == public_keys.end()) {
        throw std::runtime_error("Public key for attribute does not exist");
    }

    const pk_components_s &pk = public_keys[attr];

    oss << "attribute:" << attr << "\n";
    oss << "version:" << pk.version << "\n";
    oss << "egg_pow_alpha_delta:" << bytesToHex(pk.egg_pow_alpha_delta, BUFFER_SIZE["GT"]) << "\n";
    oss << "g_pow_y_delta:"    << bytesToHex(pk.g_pow_y_delta,    BUFFER_SIZE["G1"]) << "\n";

    return oss.str();
}

std::string Authority::generateClientKey(const std::string &clientId,
                                  const attribute_t attr) {
    int i;
    unsigned char *tmp_key = new unsigned char[BUFFER_SIZE["G1"]];
    unsigned char *tmp_L = new unsigned char[BUFFER_SIZE["ZN"]];

    if (master_keys.find(attr) == master_keys.end()) {
        std::cerr << "MK of attribute " << attr << " not found at authority "
                  << GID << std::endl;
    } else if (public_keys.find(attr) == public_keys.end()) {
        std::cerr << "PK of attribute " << attr << " not found at authority "
                  << GID << std::endl;
    } else {
        // Setup L_i
        element_t L_i;
        element_init_Zr(L_i, GP.e);

        element_random(L_i);
        L_list[attr][clientId] = new unsigned char[BUFFER_SIZE["ZN"]];
        element_to_bytes(L_list[attr][clientId], L_i);
        element_to_bytes(tmp_L, L_i);

        // Setup beta
        element_t beta_i;
        element_init_Zr(beta_i, GP.e);

        element_random(beta_i);
        beta_list[attr][clientId] = new unsigned char[BUFFER_SIZE["ZN"]];
        element_to_bytes(beta_list[attr][clientId], beta_i);

        element_t tmp_client_id_hash, tmp_client_key, tmp_g_alpha_idhash_y,
            alpha_i, y_i; //, tmp3, tmp4
        element_init_G1(tmp_client_id_hash, GP.e);
        element_init_G1(tmp_client_key, GP.e);
        // element_init_Zr(tmp3, GP.e);
        // element_init_Zr(tmp4, GP.e);
        element_init_G1(tmp_g_alpha_idhash_y, GP.e);
        element_init_Zr(alpha_i, GP.e);
        element_init_Zr(y_i, GP.e);

        element_from_bytes(alpha_i, master_keys[attr].alpha);
        element_from_bytes(y_i, master_keys[attr].y);

        /*
        element_mul(tmp3, alpha_i, beta_i);
        element_mul(tmp4, y_i, beta_i);
        element_from_hash(tmp_client_id_hash, client.GID.data(),
        static_cast<int>(client.GID.size()));
        element_pow2_zn(tmp_client_key, GP.g, tmp3, tmp_client_id_hash,
        tmp4);
        */

        std::vector<char> client_id_buffer(clientId.begin(), clientId.end());
        element_from_hash(tmp_client_id_hash, client_id_buffer.data(),
                          static_cast<int>(clientId.size()));
        // element_printf("Client ID Hash[%s] = %B\n",
        // client_id_buffer.data(),
        //    tmp_client_id_hash);
        element_pow2_zn(tmp_g_alpha_idhash_y, GP.g, alpha_i, tmp_client_id_hash,
                        y_i);

        element_pow_zn(tmp_client_key, tmp_g_alpha_idhash_y, beta_i);
        
        element_to_bytes(tmp_key, tmp_client_key);

        // element_printf("Client Key[%s] = %B\n", attr.c_str(),
        // tmp_client_key); element_printf("Client L_i[%s] = %B\n",
        // attr.c_str(), L_i);

        element_clear(L_i);
        element_clear(tmp_client_id_hash);
        element_clear(tmp_client_key);
        // element_clear(tmp3);
        // element_clear(tmp4);
        element_clear(tmp_g_alpha_idhash_y);
        element_clear(alpha_i);
        element_clear(y_i);
        element_clear(beta_i);

        return storeClientKeys(clientId, attr, tmp_key, tmp_L);
    }
    return "";
}

std::string Authority::generateClientUpdate(GlobalParameter &GP, const std::string &clientId,
                                     const attribute_t attr) {
    unsigned char *tmp_gamma = new unsigned char[BUFFER_SIZE["ZN"]];
    unsigned char *tmp_rt = new unsigned char[BUFFER_SIZE["ZN"]];
    element_t tmp_sum_L_t, tmp_hash_sum, tmp_beta_hashsum, gamma, delta_i,
        beta_i, L_i, rt_i;
    unsigned char hash_tmp[BUFFER_SIZE["ZN"]];
    element_init_Zr(gamma, GP.e);
    element_init_Zr(tmp_sum_L_t, GP.e);
    element_init_Zr(tmp_hash_sum, GP.e);
    element_init_Zr(tmp_beta_hashsum, GP.e);
    element_init_Zr(delta_i, GP.e);
    element_init_Zr(beta_i, GP.e);
    element_init_Zr(L_i, GP.e);
    element_init_Zr(rt_i, GP.e);

    element_from_bytes(L_i, L_list[attr][clientId]);
    element_from_bytes(delta_i, delta_list[attr]);
    element_from_bytes(rt_i, t_list[attr]);
    element_from_bytes(beta_i, beta_list[attr][clientId]);


    element_add(tmp_sum_L_t, L_i, rt_i);
    element_to_bytes(hash_tmp, tmp_sum_L_t);
    element_from_hash(tmp_hash_sum, hash_tmp, BUFFER_SIZE["ZN"]);
    
    element_mul(tmp_beta_hashsum, beta_i, tmp_hash_sum);
    element_div(gamma, delta_i, tmp_beta_hashsum);

    // element_printf("Client gamma[%s] = %B\n", attr.c_str(), gamma);
    // element_printf("Client rt[%s] = %B\n", attr.c_str(), rt_i);


    element_to_bytes(tmp_gamma, gamma);
    element_to_bytes(tmp_rt, rt_i);

    element_clear(tmp_sum_L_t);
    element_clear(tmp_hash_sum);
    element_clear(tmp_beta_hashsum);
    element_clear(delta_i);
    element_clear(beta_i);
    element_clear(L_i);
    element_clear(rt_i);
    element_clear(gamma);

    std::ostringstream oss;

    oss << "attribute:" << attr << "\n";
    oss << "gamma:" << bytesToHex(tmp_gamma, BUFFER_SIZE["ZN"]) << "\n";
    oss << "rt:"    << bytesToHex(tmp_rt, BUFFER_SIZE["ZN"])    << "\n";
    
    return oss.str();
}

void Authority::revokeAttribute(const std::string &clientId,
                                const attribute_t &attr) {
    deleteClientAttribute(clientId, attr);
    updatePublicKey(attr);
}

// Store new update (version = vector.size() - 1)
void Authority::storeClientUpdate(const std::string &clientId,
                                  const attribute_t &attr, unsigned char *gamma,
                                  unsigned char *random) {
    client_update_s update;
    update.gamma = new unsigned char[BUFFER_SIZE["ZN"]];
    update.random_factor = new unsigned char[BUFFER_SIZE["ZN"]];
    memcpy(update.gamma, gamma, BUFFER_SIZE["ZN"]);
    memcpy(update.random_factor, random, BUFFER_SIZE["ZN"]);

    managed_clients[clientId][attr].push_back(update);
}

// Get specific version (latest if version = -1)
uint32_t Authority::getClientUpdate(const std::string &clientId,
                                    const attribute_t &attr,
                                    client_update_s *&update,
                                    uint32_t version = -1) {
    if (!hasClient(clientId)) {
        std::cerr << "Client " << clientId << " not found" << std::endl;
        return -1;
    }
    if (!hasClientAttribute(clientId, attr)) {
        std::cerr << "Client " << clientId << " has no attribute " << attr << std::endl;
        return -1;
    }
    if (managed_clients.find(clientId) == managed_clients.end()) {
        std::cerr << "Client " << clientId << " not found in managed clients" << std::endl;
        return -1;
    }
    if (managed_clients[clientId].find(attr) ==
        managed_clients[clientId].end()) {
        std::cerr << "Client " << clientId << " has no updates for attribute " << attr << std::endl;
        return -1;
    }
    auto &updates = managed_clients[clientId][attr];
    if (updates.empty()) {
        return -1;
    }

    if (version == -1) {
        update = &updates.back(); // Latest version
        return updates.size() - 1;
    }

    if (version >= 0 && version < updates.size()) {
        update = &updates[version];
        return version;
    }

    return -1;
}

bool Authority::hasAttribute(const attribute_t attr) {
    return std::find(attributes.begin(), attributes.end(), attr) !=
           attributes.end();
}

bool Authority::hasClient(const std::string &client_id) {
    return managed_clients.find(client_id) != managed_clients.end();
}

bool Authority::hasClientAttribute(const std::string &clientId,
                                   const attribute_t &attr) {
    if (!hasClient(clientId))
        return false;
    return managed_clients[clientId].find(attr) !=
           managed_clients[clientId].end();
}

void Authority::deleteClientAttribute(const std::string &clientId,
                                      const attribute_t &attr) {
    if (!hasClient(clientId)) {
        //std::cerr << "Client " << clientId << " not found" << std::endl;
        return;
    }
    if (!hasClientAttribute(clientId, attr)) {
        //std::cerr << "Client " << clientId << " has no attribute " << attr << std::endl;
        return;
    }

    // Free memory for each update
    for (auto &update : managed_clients[clientId][attr]) {
        delete[] update.gamma;
        delete[] update.random_factor;
    }
    // Remove from map
    managed_clients[clientId].erase(attr);
    // std::cout << "Revoked attribute " << attr << " from client " <<
    // clientId
    //           << std::endl;

    // Remove the L_i and beta_i values for the client
    if (L_list.find(attr) != L_list.end() &&
        L_list[attr].find(clientId) != L_list[attr].end()) {
        delete[] L_list[attr][clientId];
        L_list[attr].erase(clientId);
    }
    if (beta_list.find(attr) != beta_list.end() &&
        beta_list[attr].find(clientId) != beta_list[attr].end()) {
        delete[] beta_list[attr][clientId];
        beta_list[attr].erase(clientId);
    }

    // If client has no attributes left, notify
    if (managed_clients[clientId].empty()) {
        std::cout << "Client " << clientId << " has no attributes left. ";
    }
}

void Authority::deleteClient(const std::string &clientId) {
    if (managed_clients.find(clientId) == managed_clients.end()) {
        //std::cerr << "Client " << clientId << " not found" << std::endl;
        return;
    }
    // delete all attributes

    for (const auto &attr_entry : managed_clients[clientId]) {
        const auto &attr = attr_entry.first;
        deleteClientAttribute(clientId, attr);
    }

    // delete client
    managed_clients.erase(clientId);

    // std::cout << "Deleted client " << clientId << std::endl;
}

std::string
Authority::storeClientKeys(const std::string &gid,
                           const std::string &attribute,
                           const unsigned char *key,
                           const unsigned char *l_i) {
    std::ostringstream oss;

    oss << "GID: " << gid << "\n";
    oss << "attribute:" << attribute << "\n";
    oss << "client_key:" << bytesToHex(key, BUFFER_SIZE["G1"]) << "\n";
    oss << "client_l_i:" << bytesToHex(l_i, BUFFER_SIZE["ZN"]) << "\n";

    return oss.str();
}

void Authority::print() const {
    // Print Authority ID
    std::cout << "Authority ID: " << GID << std::endl;

    // Print attributes and their master/public keys
    std::cout << "Number of attributes: " << attributes.size() << std::endl;
    for (const auto &attr : attributes) {
        std::cout << "\nAttribute: " << attr << std::endl;

        // Print master key components (as hex)
        std::cout << "Master Key Alpha: "
                  << bytesToHex(master_keys.at(attr).alpha, BUFFER_SIZE["ZN"])
                  << std::endl;
        std::cout << "Master Key Y: "
                  << bytesToHex(master_keys.at(attr).y, BUFFER_SIZE["ZN"])
                  << std::endl;

        // Print raw public key components
        std::cout << "Raw PK egg^alpha: "
                  << bytesToHex(raw_public_keys.at(attr).egg_pow_alpha,
                                BUFFER_SIZE["GT"])
                  << std::endl;
        std::cout << "Raw PK g^y: "
                  << bytesToHex(raw_public_keys.at(attr).g_pow_y,
                                BUFFER_SIZE["G1"])
                  << std::endl;

        // Print public key components
        std::cout << "PK egg^(alpha*delta): "
                  << bytesToHex(public_keys.at(attr).egg_pow_alpha_delta,
                                BUFFER_SIZE["GT"])
                  << std::endl;
        std::cout << "PK g^(y*delta): "
                  << bytesToHex(public_keys.at(attr).g_pow_y_delta,
                                BUFFER_SIZE["G1"])
                  << std::endl;

        // Print delta and t values
        std::cout << "Delta: "
                  << bytesToHex(delta_list.at(attr), BUFFER_SIZE["ZN"])
                  << std::endl;
        std::cout << "T: " << bytesToHex(t_list.at(attr), BUFFER_SIZE["ZN"])
                  << std::endl;

        // Print L and beta values
        if (L_list.find(attr) != L_list.end()) {
            for (const auto &client_entry : L_list.at(attr)) {
                std::cout << "  Client " << client_entry.first << ":"
                          << std::endl;
                std::cout << "    L: "
                          << bytesToHex(L_list.at(attr).at(client_entry.first),
                                        BUFFER_SIZE["ZN"])
                          << std::endl;
                std::cout << "    Beta: "
                          << bytesToHex(
                                 beta_list.at(attr).at(client_entry.first),
                                 BUFFER_SIZE["ZN"])
                          << std::endl;
            }
        }
    }

    // Print managed clients
    std::cout << "\nNumber of managed clients: " << managed_clients.size()
              << std::endl;
    for (const auto &client : managed_clients) {
        std::cout << "\nClient ID: " << client.first << std::endl;
        std::cout << "Number of attributes: " << client.second.size()
                  << std::endl;

        for (const auto &attr_entry : client.second) {
            std::cout << "  Attribute: " << attr_entry.first << std::endl;
            std::cout << "  Number of updates: " << attr_entry.second.size()
                      << std::endl;

            for (size_t i = 0; i < attr_entry.second.size(); i++) {
                std::cout << "    Update " << i << ":" << std::endl;
                std::cout << "      Gamma: "
                          << bytesToHex(attr_entry.second[i].gamma,
                                        BUFFER_SIZE["ZN"])
                          << std::endl;
                std::cout << "      Random: "
                          << bytesToHex(attr_entry.second[i].random_factor,
                                        BUFFER_SIZE["ZN"])
                          << std::endl;
            }
        }
    }
}

bool Authority::saveAuthorityState(const std::string &filename) {
    std::ofstream outFile(filename);
    if (!outFile.is_open()) {
        fprintf(stderr, "Error: Could not open file %s for writing\n",
                filename.c_str());
        return false;
    }

    // Save Authority ID
    outFile << "GID:" << GID << "\n";

    // Save attributes and their master/public keys
    outFile << "ATTR_COUNT:" << attributes.size() << "\n";
    for (const auto &attr : attributes) {
        outFile << "ATTR:" << attr << "\n";

        // Save master key
        outFile << "MK_ALPHA:"
                << bytesToHex(master_keys.at(attr).alpha, BUFFER_SIZE["ZN"])
                << "\n";
        outFile << "MK_Y:"
                << bytesToHex(master_keys.at(attr).y, BUFFER_SIZE["ZN"])
                << "\n";

        // Save raw public key
        outFile << "RAW_PK_EGG:"
                << bytesToHex(raw_public_keys.at(attr).egg_pow_alpha,
                              BUFFER_SIZE["GT"])
                << "\n";
        outFile << "RAW_PK_G:"
                << bytesToHex(raw_public_keys.at(attr).g_pow_y,
                              BUFFER_SIZE["G1"])
                << "\n";

        // Save public key
        outFile << "PK_VERSION:" << public_keys.at(attr).version << "\n";
        outFile << "PK_EGG:"
                << bytesToHex(public_keys.at(attr).egg_pow_alpha_delta,
                              BUFFER_SIZE["GT"])
                << "\n";
        outFile << "PK_G:"
                << bytesToHex(public_keys.at(attr).g_pow_y_delta,
                              BUFFER_SIZE["G1"])
                << "\n";

        // Save delta and t values
        outFile << "DELTA:"
                << bytesToHex(delta_list.at(attr), BUFFER_SIZE["ZN"]) << "\n";
        outFile << "T:" << bytesToHex(t_list.at(attr), BUFFER_SIZE["ZN"])
                << "\n";

        // Save L and beta values for each client
        size_t client_count = L_list[attr].size();
        outFile << "L_BETA_COUNT:" << client_count << "\n";
        for (const auto &client_entry : L_list[attr]) {
            outFile << "CLIENT:" << client_entry.first << "\n";
            outFile << "L:"
                    << bytesToHex(L_list[attr][client_entry.first],
                                  BUFFER_SIZE["ZN"])
                    << "\n";
            outFile << "BETA:"
                    << bytesToHex(beta_list[attr][client_entry.first],
                                  BUFFER_SIZE["ZN"])
                    << "\n";
        }
    }

    // Save managed clients
    outFile << "CLIENT_COUNT:" << managed_clients.size() << "\n";
    for (const auto &client : managed_clients) {
        outFile << "CLIENT_ID:" << client.first << "\n";
        outFile << "CLIENT_ATTR_COUNT:" << client.second.size() << "\n";

        for (const auto &attr_entry : client.second) {
            outFile << "CLIENT_ATTR:" << attr_entry.first << "\n";
            outFile << "UPDATE_COUNT:" << attr_entry.second.size() << "\n";

            for (const auto &update : attr_entry.second) {
                outFile << "GAMMA:"
                        << bytesToHex(update.gamma, BUFFER_SIZE["ZN"]) << "\n";
                outFile << "RANDOM:"
                        << bytesToHex(update.random_factor, BUFFER_SIZE["ZN"])
                        << "\n";
            }
        }
    }

    outFile.close();
    printf("Authority state saved to %s\n", filename.c_str());
    return true;
}

bool Authority::loadAuthorityState(const std::string &filename,
                                   GlobalParameter &GP, Authority &resultAuth) {
    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        fprintf(stderr, "Error: Could not open file %s for reading\n",
                filename.c_str());
        return false;
    }

    std::string line, key, value;

    // Load Authority ID
    std::getline(inFile, line);
    if (line.substr(0, 4) == "GID:") {
        resultAuth = Authority(line.substr(4));
        resultAuth.GP = GP;
    }

    // Load attributes
    std::getline(inFile, line);
    if (line.substr(0, 11) != "ATTR_COUNT:") {
        fprintf(stderr, "Error: Invalid file format - ATTR_COUNT not found\n");
        return false;
    }
    size_t attr_count = std::stoi(line.substr(11));

    for (size_t i = 0; i < attr_count; i++) {
        // Read attribute
        std::getline(inFile, line);
        if (line.substr(0, 5) != "ATTR:")
            continue;
        std::string attr = line.substr(5);
        resultAuth.attributes.push_back(attr);

        // Load master key
        std::getline(inFile, line); // MK_ALPHA
        unsigned char *master_key_alpha = new unsigned char[BUFFER_SIZE["ZN"]];
        int length;
        hexToBytes(line.substr(9), master_key_alpha, length);

        std::getline(inFile, line); // MK_Y
        unsigned char *master_key_y = new unsigned char[BUFFER_SIZE["ZN"]];
        hexToBytes(line.substr(5), master_key_y, length);

        resultAuth.master_keys[attr] = {master_key_alpha, master_key_y};

        // Load raw public key
        std::getline(inFile, line); // RAW_PK_EGG
        unsigned char *raw_public_key_egg =
            new unsigned char[BUFFER_SIZE["GT"]];
        hexToBytes(line.substr(11), raw_public_key_egg, length);

        std::getline(inFile, line); // RAW_PK_G
        unsigned char *raw_public_key_g = new unsigned char[BUFFER_SIZE["G1"]];
        hexToBytes(line.substr(9), raw_public_key_g, length);

        resultAuth.raw_public_keys[attr] = {raw_public_key_egg,
                                            raw_public_key_g};

        // Load public key
        std::getline(inFile, line); // PK_VERSION
        uint32_t version = 0;
        if (line.substr(0, 11) == "PK_VERSION:") {
            version = std::stoull(line.substr(11));
            std::getline(inFile, line); // PK_EGG
        } else {
            // For backward compatibility with files saved before version
            // was added
            printf("Warning: No version found for attribute %s, using 0\n",
                   attr.c_str());
        }

        unsigned char *public_key_egg = new unsigned char[BUFFER_SIZE["GT"]];
        hexToBytes(line.substr(7), public_key_egg, length);

        std::getline(inFile, line); // PK_G
        unsigned char *public_key_g = new unsigned char[BUFFER_SIZE["G1"]];
        hexToBytes(line.substr(5), public_key_g, length);

        pk_components_s pk_comps;
        pk_comps.version = version;
        pk_comps.egg_pow_alpha_delta = public_key_egg;
        pk_comps.g_pow_y_delta = public_key_g;
        resultAuth.public_keys[attr] = pk_comps;

        // Load delta and t values
        std::getline(inFile, line); // DELTA
        unsigned char *delta = new unsigned char[BUFFER_SIZE["ZN"]];
        hexToBytes(line.substr(6), delta, length);
        resultAuth.delta_list[attr] = delta;

        std::getline(inFile, line); // T
        unsigned char *t = new unsigned char[BUFFER_SIZE["ZN"]];
        hexToBytes(line.substr(2), t, length);
        resultAuth.t_list[attr] = t;

        // Load L and beta values
        std::getline(inFile, line); // L_BETA_COUNT
        if (line.substr(0, 13) != "L_BETA_COUNT:")
            continue;
        size_t lb_count = std::stoi(line.substr(13));

        for (size_t k = 0; k < lb_count; k++) {
            std::getline(inFile, line); // CLIENT
            std::string client_id = line.substr(7);

            std::getline(inFile, line); // L
            unsigned char *L = new unsigned char[BUFFER_SIZE["ZN"]];
            hexToBytes(line.substr(2), L, length);
            resultAuth.L_list[attr][client_id] = L;

            std::getline(inFile, line); // BETA
            unsigned char *beta = new unsigned char[BUFFER_SIZE["ZN"]];
            hexToBytes(line.substr(5), beta, length);
            resultAuth.beta_list[attr][client_id] = beta;
        }
    }

    // Load managed clients
    std::getline(inFile, line);
    if (line.substr(0, 13) != "CLIENT_COUNT:") {
        fprintf(stderr,
                "Error: Invalid file format - CLIENT_COUNT not found\n");
        return false;
    }
    size_t client_count = std::stoi(line.substr(13));

    for (size_t i = 0; i < client_count; i++) {
        // Read client ID
        std::getline(inFile, line);
        if (line.substr(0, 10) != "CLIENT_ID:")
            continue;
        std::string client_id = line.substr(10);

        // Read client attributes count
        std::getline(inFile, line);
        if (line.substr(0, 18) != "CLIENT_ATTR_COUNT:")
            continue;
        size_t client_attr_count = std::stoi(line.substr(18));

        for (size_t j = 0; j < client_attr_count; j++) {
            // Read attribute
            std::getline(inFile, line);
            if (line.substr(0, 12) != "CLIENT_ATTR:")
                continue;
            std::string attr = line.substr(12);

            // Read update count
            std::getline(inFile, line);
            if (line.substr(0, 13) != "UPDATE_COUNT:")
                continue;
            size_t update_count = std::stoi(line.substr(13));

            for (size_t k = 0; k < update_count; k++) {
                unsigned char *gamma = new unsigned char[BUFFER_SIZE["ZN"]];
                unsigned char *random = new unsigned char[BUFFER_SIZE["ZN"]];
                int length;

                std::getline(inFile, line); // GAMMA
                hexToBytes(line.substr(6), gamma, length);

                std::getline(inFile, line); // RANDOM
                hexToBytes(line.substr(7), random, length);

                resultAuth.managed_clients[client_id][attr].push_back(
                    {gamma, random});
            }
        }
    }

    inFile.close();
    printf("Authority state loaded from %s\n", filename.c_str());
    return true;
}

std::vector<uint8_t> Authority::serializeGlobalParameter(GlobalParameter& gp) {
    std::vector<uint8_t> buffer;

    int gLen = element_length_in_bytes(gp.g);
    buffer.insert(buffer.end(),
                  reinterpret_cast<uint8_t*>(&gLen),
                  reinterpret_cast<uint8_t*>(&gLen) + sizeof(gLen));

    std::vector<uint8_t> gBytes(gLen);
    element_to_bytes(gBytes.data(), gp.g);
    buffer.insert(buffer.end(), gBytes.begin(), gBytes.end());

    return buffer;
}