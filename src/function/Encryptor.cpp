#include "Encryptor.h"
#include "utils.hpp"
#include "memoryCheck.hpp"
#include <sstream>
#ifdef ESP32
#include <Arduino.h>
#endif // ESP32

MaCpAbeEncryptor::MaCpAbeEncryptor(const std::string &gid, GlobalParameter &gp)
    : MaCpAbeClient(gid, gp) {
    // init the egg_pairing_result
    initEggPairingResult();
}

MaCpAbeEncryptor::MaCpAbeEncryptor(const MaCpAbeClient &client)
    : MaCpAbeClient(client) {
    initEggPairingResult();
}

void MaCpAbeEncryptor::initEggPairingResult() {
    // Initialize egg_pairing_result with the pairing result
    if (egg_pairing_result) {
        delete[] egg_pairing_result;
    }
    egg_pairing_result = new unsigned char[BUFFER_SIZE["GT"]];
    element_t tmp_egg;
    element_init_GT(tmp_egg, GP.e);
    element_pairing(tmp_egg, GP.g, GP.g);
    element_to_bytes(egg_pairing_result, tmp_egg);
    element_clear(tmp_egg);
}

bool MaCpAbeEncryptor::encrypt(element_t &M, AccessPolicy &AC,
                               const public_key_map_t &pks,
                               const std::vector<attribute_t> &revoked_attrs,
                               bool lewko_mode, bool optimized) {
    // checkMemory("encrypt-start");

    // Debug GP
    if (!GP.e || !GP.g) {
        std::cout << "ERROR: GP not initialized!" << std::endl;
        return false;
    }
    // std::cout << "Pairing OK" << std::endl;

    element_t s, zero;
    element_init_Zr(s, GP.e);
    element_init_Zr(zero, GP.e);
    // std::cout << "Elements initialized" << std::endl;

    // Generate secret s
    element_random(s);
    // element_printf("Secret s: %B\n", s);

    // Generate message
    element_t egg, c0, tmp_egg_pow_s;
    element_init_GT(egg, GP.e);
    element_init_GT(c0, GP.e);
    element_init_GT(tmp_egg_pow_s, GP.e);
    // std::cout << "Message elements initialized" << std::endl;

    // checkMemory("before-pairing");

    if (!optimized) {
        element_pairing(egg, GP.g, GP.g);
    } else {
        element_from_bytes(egg, egg_pairing_result);
    }

    // checkMemory("after-pairing");

    element_pow_zn(tmp_egg_pow_s, egg, s);
    element_mul(c0, M, tmp_egg_pow_s);

    element_to_bytes(AC.c0, c0);

    element_clear(egg);
    element_clear(c0);
    element_clear(tmp_egg_pow_s);

    element_set0(zero);

    if (revoked_attrs.empty() || lewko_mode) {
        // std::cout << "Attributes - fill" << std::endl;
        std::vector<attribute_t> tmp_vector;

        // encrypt s in the access policy (lambda = s, omega = 0)
        if (!fillPolicy(AC.root, s, zero, pks, tmp_vector, this->root, false,
                        lewko_mode, optimized)) {
            std::cerr << ("Error in fillPolicy") << std::endl;
            return false;
        }
    } else {
        // std::cout << "Attributes - update" << std::endl;
        AccessPolicy::resetIsModifiedField(AC.root);
        updatePolicy(AC.root, revoked_attrs, s, zero, pks, this->root, false);
    }
    // std::cout << "Attributes - done" << std::endl;

    element_clear(s);
    element_clear(zero);

    // checkMemory("end-of-encrypt");

    return true;
}

bool checkAttrInPks(const public_key_map_t &pks, const attribute_t &attr) {
    auto it = pks.find(attr);
    if (it == pks.end()) {
        std::cerr << "Attribute '" << attr.c_str() << "' not found in key map!"
                  << std::endl;
        return false;
    }
    return true;
}

bool MaCpAbeEncryptor::fillPolicy(
    const std::shared_ptr<AccessPolicy::Node> &node, element_t &lambda,
    element_t &omega, const public_key_map_t &pks,
    std::vector<attribute_t> &past_attrs,
    const std::shared_ptr<ShareTree> &share_tree, bool is_stockable,
    bool lewko_mode, bool optimized) {
    // checkMemory("fillPolicy-start");
    // std::cout << "Processing node: " << node->attribute.c_str()
    //            << " (stockable: " << is_stockable << ")" << std::endl;
    // element_printf("Node lambda: %B\n", lambda);
    // element_printf("Node omega: %B\n", omega);

    if (!lewko_mode && is_stockable) {
        // std::cout << "Initializing stockable node" << std::endl;
        share_tree->initShareZr(GP);
        element_set(share_tree->lambda_share, lambda);
        element_set(share_tree->omega_share, omega);
    }
    // checkMemory("after-stock");

    if (!node->is_leaf) {
        // std::cout << "Processing non-leaf node, children: " << node->n <<
        // std::endl;

        Polynome p_lambda(GP, node->k, lambda);
        Polynome p_omega(GP, node->k, omega);

        std::vector<attribute_t> tmp_vector;
        bool is_parent_node;
        for (int i = 0; i < node->children.size(); i++) {
            element_t lambda_fils, omega_fils, index_fils;
            element_init_Zr(lambda_fils, GP.e);
            element_init_Zr(omega_fils, GP.e);
            element_init_Zr(index_fils, GP.e);

            element_set_si(index_fils, i + 1);
            p_lambda.evaluatePolynome(GP, index_fils, lambda_fils);
            p_omega.evaluatePolynome(GP, index_fils, omega_fils);

            // printf("%d\n", share_tree->test);

            is_parent_node = (node->k != 1);
            auto new_node_share = std::make_shared<ShareTree>();

            share_tree->addChild(new_node_share);

            if (!fillPolicy(node->children[i], lambda_fils, omega_fils, pks,
                            tmp_vector, share_tree->children[i],
                            is_parent_node, lewko_mode, optimized)) {
                element_clear(lambda_fils);
                element_clear(omega_fils);
                element_clear(index_fils);
                return false;
            }
            element_clear(lambda_fils);
            element_clear(omega_fils);
            element_clear(index_fils);
        }
        node->_coming_attrs = tmp_vector;
        past_attrs.insert(past_attrs.end(), tmp_vector.begin(),
                          tmp_vector.end());
    } else {
        // return if the attribute is not in the public keys
        if (!checkAttrInPks(pks, node->attribute)) {
            std::cerr << "Invalid attribute data for '"
                      << node->attribute.c_str() << "'" << std::endl;
            return false;
        }

        // std::cout << "Processing leaf node" << std::endl;

        // Send back information
        past_attrs.push_back(node->attribute);
        node->_coming_attrs = {node->attribute};

        element_t c2, r_i;
        element_init_G1(c2, GP.e);
        element_init_Zr(r_i, GP.e);

        element_random(r_i);

        // element_pp_t need a lot of memory space so a scope is used to clear
        // asap
        {
            element_pp_t g_pp;
            element_pp_init(g_pp, GP.g);
            element_pp_pow_zn(c2, r_i, g_pp);
            element_pp_clear(g_pp);
        }
        // checkMemory("after-c2");

        element_t egg, c1, c3; // c2, c3, r_i;
        element_t pk1, pk2;    //, tmp1, tmp2, result;

        element_init_GT(egg, GP.e);
        element_init_GT(c1, GP.e);
        element_init_G1(c3, GP.e);
        element_init_GT(pk1, GP.e);
        element_init_G1(pk2, GP.e);
        // checkMemory("after-init");

        if (!optimized) {
            element_pairing(egg, GP.g, GP.g);
        } else {
            element_from_bytes(egg, egg_pairing_result);
        }

        element_from_bytes(pk1, pks.at(node->attribute).egg_pow_alpha_delta);
        element_from_bytes(pk2, pks.at(node->attribute).g_pow_y_delta);

        // element_printf("pk1[%s] = %B\n", node->attribute.c_str(), pk1);
        // element_printf("pk2[%s] = %B\n", node->attribute.c_str(), pk2);

        element_pow2_zn(c1, egg, lambda, pk1, r_i);
        element_pow2_zn(c3, pk2, r_i, GP.g, omega);
        // element_printf("C1[%d] = %B\n", i, c1);
        // element_printf("C2[%d] = %B\n", i, c2);
        // element_printf("C3[%d] = %B\n", i, c3);

        // std::cout << "Calculating c1, c2, c3 done" << std::endl;
        element_to_bytes(node->c1, c1);
        element_to_bytes(node->c2, c2);
        element_to_bytes(node->c3, c3);

        /*
        element_from_hash(tmp1, this->GID.data(),
        static_cast<int>(this->GID.size()));
        element_pairing(tmp2, tmp1, GP.g);
        element_pow2_zn(result, egg, lambda, tmp2, omega);
        element_printf("Result calculated at encryption side: %B\n",
        result);
        */

        element_clear(egg);
        element_clear(c1);
        element_clear(c2);
        element_clear(c3);
        element_clear(r_i);
        element_clear(pk1);
        element_clear(pk2);
        // element_clear(tmp1);
        // element_clear(tmp2);
        // element_clear(result);
    }

    // checkMemory("after-clear-fillPolicy");
    return true;
}

void MaCpAbeEncryptor::updatePolicy(
    const std::shared_ptr<AccessPolicy::Node> &node,
    const std::vector<attribute_t> &revoked_attrs, element_t &lambda,
    element_t &omega, const public_key_map_t &pks,
    const std::shared_ptr<ShareTree> &share_tree, bool is_stockable,
    bool optimized) {

    node->is_modified = true;
    // checkMemory("updatePolicy-start");
    // std::cout << "Update node: " << node->attribute.c_str()
    //            << " (stockable: " << is_stockable << ")" << std::endl;

    if (is_stockable) {
        share_tree->initShareZr(GP);
        element_set(share_tree->lambda_share, lambda);
        element_set(share_tree->omega_share, omega);
    }
    // checkMemory("after-stock-update");
    if (node->is_leaf) {
        // Start encryption
        element_t c2, r_i;
        element_init_G1(c2, GP.e);
        element_init_Zr(r_i, GP.e);

        element_random(r_i);

        // element_pp_t need a lot of memory space so a scope is used to clear
        // asap
        {
            element_pp_t g_pp;
            element_pp_init(g_pp, GP.g);
            // checkMemory("after-init-3: g_pp");
            element_pp_pow_zn(c2, r_i, g_pp);
            element_pp_clear(g_pp);
            // checkMemory("after-calc-c2 and cleared g_pp");
        }

        element_t egg, c1, c3, pk1, pk2; // tmp1, tmp2, result; // c2, r_i
        // element_pp_t g_pp;

        element_init_GT(egg, GP.e);
        element_init_GT(c1, GP.e);
        // element_init_G1(c2, GP.e);
        element_init_G1(c3, GP.e);
        element_init_GT(pk1, GP.e);
        element_init_G1(pk2, GP.e);
        // element_init_Zr(r_i, GP.e);
        // element_init_G1(tmp1, GP.e);
        // element_init_GT(tmp2, GP.e);
        // element_init_GT(result, GP.e);
        // element_pp_init(g_pp, GP.g);

        if (!optimized) {
            element_pairing(egg, GP.g, GP.g);
        } else {
            element_from_bytes(egg, egg_pairing_result);
        }

        // Calculate c1, c2, c3
        // element_random(r_i);
        element_from_bytes(pk1, pks.at(node->attribute).egg_pow_alpha_delta);
        element_from_bytes(pk2, pks.at(node->attribute).g_pow_y_delta);

        element_pow2_zn(c1, egg, lambda, pk1, r_i);
        // element_printf("C1[%d] = %B\n", i, c1);
        // element_pp_pow_zn(c2, r_i, g_pp);
        // element_printf("C2[%d] = %B\n", i, c2);
        element_pow2_zn(c3, pk2, r_i, GP.g, omega);
        // element_printf("C3[%d] = %B\n", i, c3);

        element_to_bytes(node->c1, c1);
        element_to_bytes(node->c2, c2);
        element_to_bytes(node->c3, c3);

        // std::vector<char> buffer(this->GID.begin(), this->GID.end());
        // element_from_hash(tmp1, buffer.data(),
        //                   static_cast<int>(this->GID.size()));
        // element_pairing(tmp2, tmp1, GP.g);
        // element_pow2_zn(result, egg, lambda, tmp2, omega);
        // element_printf("Result in decryption[%s]: %B\n",
        // node->attribute.c_str(), result);

        element_clear(egg);
        element_clear(c1);
        element_clear(c2);
        element_clear(c3);
        element_clear(r_i);
        element_clear(pk1);
        element_clear(pk2);
        // element_clear(tmp1);
        // element_clear(tmp2);
        // element_clear(result);
        // element_pp_clear(g_pp);

    } else if (node->k == 1) { // OR node
        for (int i = 0; i < node->children.size(); i++) {
            updatePolicy(node->children[i], revoked_attrs, lambda, omega, pks,
                         share_tree->children[i], false, optimized);
        }
    } else if (node->k == node->n) { // AND node
        std::vector<int> index_branch = {};
        int j;
        for (int i = 0; i < node->children.size(); i++) {
            j = 0;
            while (j < revoked_attrs.size()) {
                auto it = std::find(node->children[i]->_coming_attrs.begin(),
                                    node->children[i]->_coming_attrs.end(),
                                    revoked_attrs[j]);
                if (it != node->children[i]->_coming_attrs.end())
                    break;
                j++;
            }
            if (j < revoked_attrs.size())
                index_branch.push_back(i);
        }

        // for (const auto &val : index_branch)
        //     std::cout << val << ", ";
        // std::cout << std::endl;

        if (index_branch.size() == node->n) {
            Polynome p_lambda(GP, node->k, lambda);
            Polynome p_omega(GP, node->k, omega);

            std::vector<attribute_t> tmp_vector;
            for (int i = 0; i < node->children.size(); i++) {
                element_t lambda_fils, omega_fils, index_fils;
                element_init_Zr(lambda_fils, GP.e);
                element_init_Zr(omega_fils, GP.e);
                element_init_Zr(index_fils, GP.e);

                element_set_si(index_fils, i + 1);
                p_lambda.evaluatePolynome(GP, index_fils, lambda_fils);
                p_omega.evaluatePolynome(GP, index_fils, omega_fils);

                // printf("%d\n", share_tree->test);

                updatePolicy(node->children[i], revoked_attrs, lambda_fils,
                             omega_fils, pks, share_tree->children[i], true,
                             optimized);
            }
        } else {
            // From here, code is specific to 'AND/OR'
            int node_z;
            if (index_branch.size() != 0) {
                node_z = index_branch[0];
            } else {
                if (node->children[0]->_coming_attrs.size() <
                    node->children[1]->_coming_attrs.size())
                    node_z = 1;
                else
                    node_z = 0;
            }

            element_t x_i, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, res1, res2;
            element_init_Zr(x_i, GP.e);
            element_init_Zr(tmp1, GP.e);
            element_init_Zr(tmp2, GP.e);
            element_init_Zr(tmp3, GP.e);
            element_init_Zr(tmp4, GP.e);
            element_init_Zr(tmp5, GP.e);
            element_init_Zr(tmp6, GP.e);
            element_init_Zr(res1, GP.e);
            element_init_Zr(res2, GP.e);

            if (node_z == 0) {
                element_set1(tmp1);
                element_neg(x_i, tmp1);
                element_set_si(tmp4, 2);

                element_mul(tmp2, share_tree->children[1]->lambda_share, x_i);
                element_mul(tmp3, share_tree->children[1]->omega_share, x_i);
                element_sub(tmp5, lambda, tmp2);
                element_sub(tmp6, omega, tmp3);
                element_div(res1, tmp5, tmp4);
                element_div(res2, tmp6, tmp4);
            } else {
                element_set_si(x_i, 2);

                element_mul(tmp2, share_tree->children[0]->lambda_share, x_i);
                element_mul(tmp3, share_tree->children[0]->omega_share, x_i);
                element_sub(tmp4, lambda, tmp2);
                element_sub(tmp5, omega, tmp3);
                element_neg(res1, tmp4);
                element_neg(res2, tmp5);
            }

            updatePolicy(node->children[node_z], revoked_attrs, res1, res2, pks,
                         share_tree->children[node_z], true, optimized);

            element_clear(x_i);
            element_clear(tmp1);
            element_clear(tmp2);
            element_clear(tmp3);
            element_clear(tmp4);
            element_clear(tmp5);
            element_clear(tmp6);
            element_clear(res1);
            element_clear(res2);
        }
    }
}

void MaCpAbeEncryptor::deserializePublicKey(const std::string &input,
                                            public_key_map_t &public_keys) {
    std::istringstream iss(input);
    std::string line;
    std::string attr;
    std::string hex_egg, hex_g;
    uint32_t version = 0;

    // Parse serialized string
    while (std::getline(iss, line)) {
        if (line.rfind("attribute:", 0) == 0) {
            attr = line.substr(10); // skip "attribute:"
        } else if (line.rfind("version:", 0) == 0) {
            version = std::stoul(line.substr(8));
        } else if (line.rfind("egg_pow_alpha_delta:", 0) == 0) {
            hex_egg = line.substr(20);
        } else if (line.rfind("g_pow_y_delta:", 0) == 0) {
            hex_g = line.substr(14);
        }
    }

    if (attr.empty()) {
        throw std::runtime_error("Attribute missing in serialized public key");
    }

    // Allocate memory for byte arrays
    unsigned char *egg_bytes = new unsigned char[BUFFER_SIZE["GT"]];
    unsigned char *g_bytes   = new unsigned char[BUFFER_SIZE["G1"]];

    hexToBytes(hex_egg, egg_bytes, BUFFER_SIZE["GT"]);
    hexToBytes(hex_g, g_bytes, BUFFER_SIZE["G1"]);

    // If the attribute already exists, free old memory to avoid leaks
    if (public_keys.find(attr) != public_keys.end()) {
        delete[] public_keys[attr].egg_pow_alpha_delta;
        delete[] public_keys[attr].g_pow_y_delta;
    }

    // Store in the provided map
    pk_components_s pk;
    pk.version = version;
    pk.egg_pow_alpha_delta = egg_bytes;
    pk.g_pow_y_delta = g_bytes;

    public_keys[attr] = pk;
}

