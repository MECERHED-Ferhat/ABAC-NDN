#include "Client.h"

#include "utils.hpp"
#include <algorithm>
#include <cstring>
#include <random>

#include "Polynome.h"

// Add compiler version checks
#if defined(__cplusplus)
#if __cplusplus < 201703L
#warning "C++17 or higher is required"
#endif
#endif

// Client class
void MaCpAbeClient::ShareTree::initShareZr(GlobalParameter &GP) {
    element_init_Zr(lambda_share, GP.e);
    element_init_Zr(omega_share, GP.e);
}

void MaCpAbeClient::ShareTree::initResultGT(GlobalParameter &GP) {
    element_init_GT(saved_result, GP.e);
}

void MaCpAbeClient::ShareTree::addChild(std::shared_ptr<ShareTree> child) {
    children.push_back(child);
}

MaCpAbeClient::MaCpAbeClient(const std::string &gid, GlobalParameter &gp)
    : GID(gid), GP(gp) {
    root = std::make_shared<ShareTree>();
    symmetric_key = nullptr;
}



#ifdef ESP32 // on ESP32, the hardware RNG is used
unsigned int MaCpAbeClient::generateRandomNumber() {
    // Generate a random number using the ESP32 hardware RNG
    unsigned int randNum = esp_random() & 0xFFFF; // Mask to 16 bits (0 - 65535)
    // printf("Random number generated: %u\n", randNum);

    return randNum;
}
#else
unsigned int MaCpAbeClient::generateRandomNumber() {
    std::random_device rd;
    std::mt19937 gen(rd());

    std::uniform_int_distribution<unsigned int> dis(0, 65535);

    return dis(gen);
}
#endif // ARDUINO

void MaCpAbeClient::generateKeyMaterial(element_t &input) {
    unsigned char buffer1[BUFFER_SIZE["GT"]];

    element_init_Zr(key_material, GP.e);
    element_to_bytes(buffer1, input);
    element_from_hash(key_material, buffer1, BUFFER_SIZE["GT"]);
}

void MaCpAbeClient::deriveSymmetricKey(const unsigned int random_number,
                                       const size_t length) {
    this->symmetric_key = new unsigned char[length];
    unsigned char buffer[BUFFER_SIZE["ZN"]];
    element_t random_element, tmp_result;

    element_init_Zr(random_element, GP.e);
    element_init_Zr(tmp_result, GP.e);
    element_set_si(random_element, random_number);

    element_mul(tmp_result, key_material, random_element);
    element_to_bytes(buffer, tmp_result);
    std::memcpy(this->symmetric_key, buffer, length);
}

void MaCpAbeClient::buildTree(const std::shared_ptr<AccessPolicy::Node> &node,
                              const std::shared_ptr<ShareTree> &share_tree) {
    for (int i = 0; i < node->n; i++) {
        auto new_node_share = std::make_shared<MaCpAbeClient::ShareTree>();
        share_tree->addChild(new_node_share);
        buildTree(node->children[i], share_tree->children[i]);
    }
}

void MaCpAbeClient::deserializeGlobalParameter(GlobalParameter& gp, std::vector<uint8_t>& buffer) {
    const std::string param_file = "a.param";
    std::ifstream f(param_file, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Cannot open pairing parameter file: " + param_file);

    char pairing_param[1024];
    f.read(pairing_param, sizeof(pairing_param));
    size_t count = f.gcount();
    f.close();
    if (!count) pbc_die("input error");

    pairing_init_set_buf(gp.e, pairing_param, count);
    if (!pairing_is_symmetric(gp.e)) pbc_die("pairing must be symmetric");

    element_t e_G1, e_GT, e_Zr;
    element_init_G1(e_G1, gp.e);
    element_init_GT(e_GT, gp.e);
    element_init_Zr(e_Zr, gp.e);

    BUFFER_SIZE["G1"] = element_length_in_bytes(e_G1);
    BUFFER_SIZE["GT"] = element_length_in_bytes(e_GT);
    BUFFER_SIZE["ZN"] = element_length_in_bytes(e_Zr);

    element_clear(e_G1);
    element_clear(e_GT);
    element_clear(e_Zr);

    size_t offset = 0;

    int gLen;
    memcpy(&gLen, buffer.data() + offset, sizeof(gLen));
    offset += sizeof(gLen);

    element_init_G1(gp.g, gp.e);
    element_from_bytes(gp.g, buffer.data() + offset);
}