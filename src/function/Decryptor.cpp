#include "Decryptor.h"

#include "memoryCheck.hpp"
#include "utils.hpp"
#include <cstring>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <string>

MaCpAbeDecryptor::MaCpAbeDecryptor(const std::string &gid, GlobalParameter &gp)
    : MaCpAbeClient(gid, gp) {
    // init the gid_hash
    init_gid_hash();
}

void MaCpAbeDecryptor::decrypt(const AccessPolicy &AC,
                               const client_key_map_t keys, element_t &M,
                               bool lewko_mode, bool optimized) {
    element_t result, tmp_c0;
    element_init_GT(result, GP.e);
    element_init_GT(tmp_c0, GP.e);

    decryptNode(AC.root, keys, result, this->root, false, lewko_mode,
                optimized);
    element_from_bytes(tmp_c0, AC.c0);
    element_div(M, tmp_c0, result);

    element_clear(result);
    element_clear(tmp_c0);
}

void MaCpAbeDecryptor::loadClientKeys(std::vector<std::string> attributes) {
    for (const auto& attr : attributes) {
      std::ostringstream filename;
      filename << attr << "_key.txt";

      std::ifstream keyFile(filename.str());
      if (!keyFile.is_open()) {
      std::cerr << "Error opening key file: " << filename.str() << std::endl;
      continue;
      }

      std::stringstream buffer;
      buffer << keyFile.rdbuf();
      std::string rawClientKey = buffer.str();
      keyFile.close();

      loadClientKey(rawClientKey);

      std::cout << "Loaded key for attribute: " << attr << std::endl;
    }
}

void MaCpAbeDecryptor::loadClientKey(const std::string &rawClientKey) {
    std::istringstream iss(rawClientKey);
    std::string line;
    std::string gid, attribute, hex_key, hex_l_i;

    while (std::getline(iss, line)) {
        if (line.rfind("GID:", 0) == 0) {
            gid = line.substr(4); // skip "GID:"
            // optional: trim whitespace
        } else if (line.rfind("attribute:", 0) == 0) {
            attribute = line.substr(10);
        } else if (line.rfind("client_key:", 0) == 0) {
            hex_key = line.substr(11);
        } else if (line.rfind("client_l_i:", 0) == 0) {
            hex_l_i = line.substr(11);
        }
    }

    // Convert hex back to bytes
    unsigned char *key = new unsigned char[BUFFER_SIZE["G1"]];
    hexToBytes(hex_key, key, BUFFER_SIZE["G1"]);

    unsigned char *l_i = new unsigned char[BUFFER_SIZE["ZN"]];
    hexToBytes(hex_l_i, l_i, BUFFER_SIZE["ZN"]);


    // Call addClientKey (make sure the memory stays valid, not temporary)
    addClientKey(key, l_i, attribute);
}

void MaCpAbeDecryptor::addClientKey(unsigned char *key, unsigned char *L_i,
                                    const attribute_t &attr) {
    attributes.push_back(attr);
    client_key[attr] = key;
    client_l_i[attr] = L_i;
}

void MaCpAbeDecryptor::loadClientUpdate(const std::string &input) {
    std::istringstream iss(input);
    std::string line;
    std::string attr, hex_gamma, hex_rt;
    uint32_t version = 0;

    // Parse serialized string
    while (std::getline(iss, line)) {
        if (line.rfind("attribute:", 0) == 0) {
            attr = line.substr(10); // skip "attribute:"
        } else if (line.rfind("version:", 0) == 0) {
            version = std::stoul(line.substr(8));
        } else if (line.rfind("gamma:", 0) == 0) {
            hex_gamma = line.substr(6);
        } else if (line.rfind("rt:", 0) == 0) {
            hex_rt = line.substr(3);
        }
    }


    // Allocate temporary buffers
    unsigned char *gamma = new unsigned char[BUFFER_SIZE["ZN"]];
    unsigned char *rt    = new unsigned char[BUFFER_SIZE["ZN"]];

    hexToBytes(hex_gamma, gamma, BUFFER_SIZE["ZN"]);
    hexToBytes(hex_rt, rt, BUFFER_SIZE["ZN"]);

    setClientUpdate(version, gamma, rt, attr);

    // Free the temporary buffers
    delete[] gamma;
    delete[] rt;
}

void MaCpAbeDecryptor::setClientUpdate(uint32_t version, unsigned char *gamma,
                                       unsigned char *random_factor,
                                       const attribute_t &attr) {
    // deep copy
    unsigned char *gamma_copy = new unsigned char[BUFFER_SIZE["ZN"]];
    unsigned char *random_factor_copy = new unsigned char[BUFFER_SIZE["ZN"]];
    std::memcpy(gamma_copy, gamma, BUFFER_SIZE["ZN"]);
    std::memcpy(random_factor_copy, random_factor, BUFFER_SIZE["ZN"]);

    // std::cout << "Set update for attribute: " << attr
    //           << ", version: " << version << std::endl;

    client_update_s update = {gamma_copy, random_factor_copy};
    client_update[attr][version] = update;

    // Update resulting key
    // element_t tmp4;
    // element_init_G1(tmp4, GP.e);

    element_t tmp1;
    element_t l_i;
    element_t t_i;
    element_init_Zr(tmp1, GP.e);
    element_init_Zr(l_i, GP.e);
    element_init_Zr(t_i, GP.e);

    element_from_bytes(l_i, client_l_i[attr]);
    element_from_bytes(t_i, random_factor);
    element_add(tmp1, l_i, t_i);


    unsigned char tmp_hash[BUFFER_SIZE["ZN"]];
    element_to_bytes(tmp_hash, tmp1);
    element_clear(tmp1);

    element_t tmp2;
    element_init_Zr(tmp2, GP.e);
    element_from_hash(tmp2, tmp_hash, BUFFER_SIZE["ZN"]);

    element_t tmp3;
    element_t g_i;
    element_init_Zr(tmp3, GP.e);
    element_init_Zr(g_i, GP.e);
    element_from_bytes(g_i, gamma);
    element_mul(tmp3, g_i, tmp2);
    element_clear(tmp2);

    element_t key_final;
    element_t key_i;
    element_init_G1(key_final, GP.e);
    element_init_G1(key_i, GP.e);
    element_from_bytes(key_i, client_key[attr]);
    element_pow_zn(key_final, key_i, tmp3);

    // element_printf("Key_i: %B\n", key_i);
    // element_printf("L_i: %B\n", l_i);
    // element_printf("Gamma_i: %B\n", g_i);
    // element_printf("T_i: %B\n", t_i);
    // element_printf("Key_final: %B\n", key_final);

    element_clear(g_i);
    element_clear(t_i);
    element_clear(l_i);
    element_clear(tmp3);
    element_clear(key_i);

    /*
    element_from_bytes(tmp1, beta_i);
    element_from_bytes(tmp2, delta_i);
    element_invert(tmp3, tmp1);
    element_pow_zn(tmp4, key_i, tmp3); // Key without beta
    element_pow_zn(key_final, tmp4, tmp2); // Key without secret delta
    */

    client_key_final[attr] = new unsigned char[BUFFER_SIZE["G1"]];
    element_to_bytes(client_key_final[attr], key_final);
    element_clear(key_final);

    // element_clear(tmp4);
}

// serialize the MaCpAbeClient object to string
std::string MaCpAbeDecryptor::serialize() const {
    std::ostringstream oss;
    oss << "GID: " << GID << "\n";
    for (const auto &attr : attributes) {
        oss << "attribute:" << attr << "\n";

        auto it_key = client_key.find(attr);
        if (it_key != client_key.end()) {
            oss << "client_key:"
                << bytesToHex(it_key->second, BUFFER_SIZE["G1"]) << "\n";
        } else {
            oss << "client_key: (not found)\n";
        }

        auto it_l_i = client_l_i.find(attr);
        if (it_l_i != client_l_i.end()) {
            oss << "client_l_i:"
                << bytesToHex(it_l_i->second, BUFFER_SIZE["ZN"]) << "\n";
        } else {
            oss << "client_l_i: (not found)\n";
        }
    }
    return oss.str();
}

// construct a MaCpAbeClient from a serialized string
MaCpAbeDecryptor MaCpAbeDecryptor::deserialize(const std::string &data,
                                               GlobalParameter &gp) {
    std::istringstream input(data);
    std::string line, gid;
    std::getline(input, line);

    // extract GID and create MaCpAbeClient object
    gid = splitLine(line).second;
    MaCpAbeDecryptor client(gid, gp);

    while (true) {
        std::string attr_line, key_line, l_i_line;

        // try to read 3 lines
        if (!std::getline(input, attr_line))
            break;
        if (!std::getline(input, key_line))
            break;
        if (!std::getline(input, l_i_line))
            break;

        // read attribute, key and L_i
        auto [attr_key, attr] = splitLine(attr_line);
        auto [key_key, key_hex] = splitLine(key_line);
        auto [l_i_key, l_i_hex] = splitLine(l_i_line);

        // check if the lines are valid
        if (attr_key != "attribute" || key_key != "client_key" ||
            l_i_key != "client_l_i" || key_hex == "(not found)" ||
            l_i_hex == "(not found)") {
            std::cerr << "invalid client format!" << std::endl;
            continue;
        }

        // hex to bytes
        unsigned char *key_ptr = new unsigned char[BUFFER_SIZE["G1"]];
        unsigned char *l_i_ptr = new unsigned char[BUFFER_SIZE["ZN"]];
        hexToBytes(key_hex, key_ptr, BUFFER_SIZE["G1"]);
        hexToBytes(l_i_hex, l_i_ptr, BUFFER_SIZE["ZN"]);

        client.addClientKey(key_ptr, l_i_ptr, attr);
    }

    return client;
}

int MaCpAbeDecryptor::evaluatePolicy(const std::shared_ptr<AccessPolicy::Node> &node) {
    if (!node->is_leaf) {
        int diff, num = 0, tmp;

        node->_satisfied_node_index = {};
        for (int i = 0; i < node->n; i++) {
            tmp = evaluatePolicy(node->children[i]);
            num += tmp;
            if (tmp)
                node->_satisfied_node_index.push_back(i);

            diff = node->k - num;
            if (diff <= 0)
                return 1;
            else if (node->n - i - 1 - diff < 0)
                return 0;
        }
        return 0;
    } else {
        if (std::find(this->attributes.begin(), this->attributes.end(),
                      node->attribute) != this->attributes.end())
            return 1;
        else
            return 0;
    }
}

int MaCpAbeDecryptor::evaluatePolicy(const AccessPolicy &AC) {
    if (AC.root == nullptr) {
        std::cerr << "Error: AccessPolicy root is null" << std::endl;
        return 0;
    }

    // Evaluate the policy
    return evaluatePolicy(AC.root);
}

void MaCpAbeDecryptor::decryptNode(
    const std::shared_ptr<AccessPolicy::Node> &node,
    const client_key_map_t keys, element_t &result,
    const std::shared_ptr<ShareTree> &share_tree, bool is_stockable,
    bool lewko_mode, bool optimized) {

    // Check for null node
    if (!node) {
        std::cerr << "Error: Null node in decryptNode" << std::endl;
        element_set0(result);
        return;
    }

    // checkMemory("start of decryptNode");

    // Check if we have a valid share tree
    if (!share_tree) {
        std::cerr << "Error: Null share_tree in decryptNode" << std::endl;
        element_set0(result);
        return;
    }

    if (!lewko_mode && !node->is_modified) {
        // Make sure saved_result exists before trying to use it
        if (!share_tree->has_result) {
            std::cerr << "Error: Share tree has no saved result" << std::endl;
            element_set0(result);
            return;
        }
        element_set(result, share_tree->saved_result);
        return;
    }

    if (!node->is_leaf) {
        // std::cout << "Decrypting threshold node: " <<
        // (node->attribute.empty() ? "[empty]" : node->attribute)
        //           << std::endl;

        // Check if node is properly initialized
        if (node->n <= 0 || node->k <= 0) {
            std::cerr << "Error: Invalid threshold values k=" << node->k
                      << ", n=" << node->n << std::endl;
            element_set0(result);
            return;
        }

        // Make sure share_tree has valid children
        if (share_tree->children.size() < node->n) {
            std::cerr << "Error: share_tree has " << share_tree->children.size()
                      << " children, but node requires " << node->n
                      << std::endl;
            element_set0(result);
            return;
        }

        std::vector<element_t> satisfied_node_result(node->n);

        for (const auto &i : node->_satisfied_node_index) {
            // Validate index
            if (i < 0 || i >= node->n || i >= node->children.size()) {
                std::cerr << "Error: Invalid satisfied node index: " << i
                          << std::endl;
                element_set0(result);
                return;
            }

            // Make sure child node exists
            if (!node->children[i]) {
                std::cerr << "Error: Null child node at index " << i
                          << std::endl;
                element_set0(result);
                return;
            }

            // Make sure share_tree child exists
            if (!share_tree->children[i]) {
                std::cerr << "Error: Null share_tree child at index " << i
                          << std::endl;
                element_set0(result);
                return;
            }

            element_t result_fils;
            element_init_GT(result_fils, GP.e);
            element_init_GT(satisfied_node_result[i], GP.e);

            bool is_parent_node;
            if (lewko_mode) {
                is_parent_node = false;
            } else {
                is_parent_node = (node->k != 1);
            }
            // checkMemory("before decryptNode recursive call");

            decryptNode(node->children[i], keys, result_fils,
                        share_tree->children[i], is_parent_node, lewko_mode,
                        optimized);
            element_set(satisfied_node_result[i], result_fils);

            element_clear(result_fils);
        }

        // Do the interpolation
        element_set1(result);

        element_t l_i, x_i, x_j, tmp1, tmp2, tmp3, res1, res2;
        element_init_Zr(l_i, GP.e);
        element_init_Zr(x_i, GP.e);
        element_init_Zr(x_j, GP.e);
        element_init_Zr(tmp1, GP.e);
        element_init_Zr(tmp2, GP.e);
        element_init_Zr(tmp3, GP.e);
        element_init_GT(res1, GP.e);
        element_init_GT(res2, GP.e);

        for (int i = 0; i < node->k; i++) {
            element_set_si(x_i, node->_satisfied_node_index[i] + 1);
            element_set1(l_i);
            for (int j = 0; j < node->k; j++) {
                if (i != j) {
                    element_set_si(x_j, node->_satisfied_node_index[j] + 1);
                    element_sub(tmp1, x_j, x_i);
                    element_div(tmp2, x_j, tmp1);
                    element_mul(tmp3, l_i, tmp2);
                    element_set(l_i, tmp3);
                }
            }
            element_pow_zn(
                res1, satisfied_node_result[node->_satisfied_node_index[i]],
                l_i);
            element_mul(res2, result, res1);
            element_set(result, res2);
        }

        if (is_stockable) {
            share_tree->initResultGT(GP);
            element_set(share_tree->saved_result, result);
            share_tree->has_result = true;
        }

        element_clear(l_i);
        element_clear(x_i);
        element_clear(x_j);
        element_clear(tmp1);
        element_clear(tmp2);
        element_clear(tmp3);
        element_clear(res1);
        element_clear(res2);

    } else {
        // std::cout << "Decrypting leaf node: " << (node->attribute.empty() ?
        // "[empty]" : node->attribute)
        //           << std::endl;

        // Check attribute
        if (node->attribute.empty()) {
            std::cerr << "Error: Leaf node has empty attribute" << std::endl;
            element_set0(result);
            return;
        }

        // Check if key exists
        if (keys.find(node->attribute) == keys.end()) {
            std::cerr << "Error: attribute " << node->attribute
                      << " not found in keys" << std::endl;
            element_set0(result);
            return;
        }

        // Check if c1, c2, c3 are valid
        if (!node->c1 || !node->c2 || !node->c3) {
            std::cerr << "Error: Leaf node " << node->attribute
                      << " has null c1, c2, or c3" << std::endl;
            element_set0(result);
            return;
        }

        std::vector<char> buffer(this->GID.begin(), this->GID.end());

        // checkMemory("before hash");

        element_t hgid;
        element_init_G1(hgid, GP.e);
        if (!optimized) {
            element_from_hash(hgid, buffer.data(),
                              static_cast<int>(this->GID.size()));
        } else {
            element_from_bytes(hgid, gid_hash);
        }

        // checkMemory("after hash");

        element_t tmp1;
        {
            element_t c3;
            element_init_G1(c3, GP.e);
            element_init_GT(tmp1, GP.e);
            element_from_bytes(c3, node->c3);
            element_pairing(tmp1, hgid, c3);
            element_clear(c3);
        }
        element_clear(hgid);

        element_t tmp2;
        {
            element_t c1;
            element_init_GT(c1, GP.e);
            element_init_GT(tmp2, GP.e);
            element_from_bytes(c1, node->c1);
            element_mul(tmp2, c1, tmp1);
            element_clear(c1);
        }
        element_clear(tmp1);

        element_t tmp3;
        {
            element_t k_i;
            element_t c2;
            element_init_G1(c2, GP.e);
            element_init_GT(tmp3, GP.e);
            element_init_G1(k_i, GP.e);
            element_from_bytes(k_i, keys.at(node->attribute));
            element_from_bytes(c2, node->c2);
            element_pairing(tmp3, k_i, c2);
            element_clear(c2);
            element_clear(k_i);
        }
        element_div(result, tmp2, tmp3);

        element_clear(tmp2);
        element_clear(tmp3);

        if (is_stockable && !lewko_mode) {
            share_tree->initResultGT(GP);
            element_set(share_tree->saved_result, result);
            share_tree->has_result = true;
        }
    }
}

void MaCpAbeDecryptor::printClient() const {
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Client ID: " << GID << std::endl;
    for (const auto &attr : attributes) {
        std::cout << "Attribute: " << attr << std::endl;
        std::cout << "Client Key: "
                  << bytesToHex(client_key.at(attr), BUFFER_SIZE["G1"])
                  << std::endl;
        std::cout << "Client L_i: "
                  << bytesToHex(client_l_i.at(attr), BUFFER_SIZE["ZN"])
                  << std::endl;
    }
    for (const auto &attr : attributes) {
        if (client_key_final.find(attr) == client_key_final.end()) {
            std::cout << "Attribute: " << attr
                      << " not found in client key final" << std::endl;
            continue;
        }

        std::cout << "Client Key Final: "
                  << bytesToHex(client_key_final.at(attr), BUFFER_SIZE["G1"])
                  << std::endl;
    }
    if (symmetric_key != nullptr) {
        std::cout << "Symmetric Key: "
                  << bytesToHex(symmetric_key, MA_CP_ABE_DEFAULT_KEYLENGTH)
                  << std::endl;
    } else {
        std::cout << "Symmetric Key: (not generated yet)" << std::endl;
    }

    if (root != nullptr) {
        std::cout << "Share Tree: set" << std::endl;
    } else {
        std::cout << "Share Tree: (not generated yet)" << std::endl;
    }

    std::cout << "Client Update: " << std::endl;
    for (const auto &attr : attributes) {
        if (client_update.find(attr) == client_update.end()) {
            std::cout << "Attribute: " << attr << " not found in client update"
                      << std::endl;
            continue;
        }

        if (client_update.at(attr).empty()) {
            std::cout << "Attribute: " << attr << " has no client update data"
                      << std::endl;
            continue;
        }

        std::cout << "Attribute: " << attr << std::endl;

        for (const auto &[version, update] : client_update.at(attr)) {
            std::cout << "  Version: " << version << std::endl;
            std::cout << "    Gamma: "
                      << bytesToHex(update.gamma, BUFFER_SIZE["ZN"])
                      << std::endl;
            std::cout << "    Random Factor: "
                      << bytesToHex(update.random_factor, BUFFER_SIZE["ZN"])
                      << std::endl;
        }
    }
    std::cout << "Reference: " << std::endl;
    for (const auto &attr : attributes) {
        if (reference.find(attr) == reference.end()) {
            std::cout << "Attribute: " << attr << " not found in reference"
                      << std::endl;
            continue;
        }
        std::cout << "Attribute: " << attr
                  << " Authority: " << reference.at(attr) << std::endl;
    }

    std::cout << "End of Client" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
}

void MaCpAbeDecryptor::init_gid_hash() {
    if (gid_hash) {
        delete[] gid_hash;
    }
    gid_hash = new unsigned char[BUFFER_SIZE["G1"]];
    std::vector<char> buffer(this->GID.begin(), this->GID.end());
    element_t tmp_gid;
    element_init_G1(tmp_gid, GP.e);
    element_from_hash(tmp_gid, buffer.data(),
                      static_cast<int>(this->GID.size()));
    element_to_bytes(gid_hash, tmp_gid);
    element_clear(tmp_gid);
}
