#ifndef MACPABE_DECRYPTOR_HPP
#define MACPABE_DECRYPTOR_HPP

#include "AccessPolicy.h"
#include "Client.h"
#include <algorithm>
#include <string>

/**
 * @brief Decryptor class for Ciphertext-Policy Attribute-Based Encryption
 * (CP-ABE)
 *
 * This class implements the decryptor-side functionality of the CP-ABE system.
 * It handles decryption operations based on access policies and attribute keys.
 * The decryptor must possess the required attributes to satisfy the access
 * policy in order to successfully decrypt the data.
 */
class MaCpAbeDecryptor : public MaCpAbeClient {
  public:
    std::vector<attribute_t> attributes; ///< MaCpAbeClient's attributes

    client_key_map_t client_key; ///< MaCpAbeClient's attribute keys
    client_key_map_t client_l_i; ///< L_i values for attributes
    client_key_map_t
        client_key_final; ///< Final client keys calculated from updates
    client_update_map_t client_update; ///< Update information
    unsigned char *gid_hash = nullptr; ///< Hash of the global identifier

    /**
     * @brief Construct a new MaCpAbeDecryptor with a given global identifier
     * @param gid Global identifier string for the decryptor
     * @param gp Global parameters for cryptographic operations
     */
    explicit MaCpAbeDecryptor(const std::string &gid, GlobalParameter &gp);

    void loadClientKeys(std::vector<std::string> attributes);

    void loadClientKey(const std::string &rawClientKey);

    /**
     * @brief Add a key and L_i value for an attribute
     * @param key Clientnt key for the attribute
     * @param L_i L_i value for the attribute
     * @param attr Attribute string
     */
    void addClientKey(unsigned char *key, unsigned char *L_i,
                      const attribute_t &attr);

    void loadClientUpdate(const std::string &input);

    /**
     * @brief Set update information for an attribute
     * @param gamma Gamma value for update
     * @param random_factor Random factor for update
     * @param attr Attribute string
     */
    void setClientUpdate(uint32_t version, unsigned char *gamma,
                         unsigned char *random_factor, const attribute_t &attr);

    /**
     * @brief Decrypt data using CP-ABE
     *
     * Performs decryption of data that was encrypted using CP-ABE. The
     * decryption will only succeed if the decryptor's attributes satisfy the
     * access policy.
     *
     * @param GP Global system parameters used for cryptographic operations
     * @param AC Access control policy that must be satisfied for decryption
     * @param keys Map of attribute keys owned by the decryptor
     * @param M Output parameter that will contain the decrypted message element
     */
    void decrypt(const AccessPolicy &AC, const client_key_map_t keys,
                 element_t &M, bool lewko_mode = false, bool optimized = false);

    /**
     * @brief Serialize the client object to string
     * @return Serialized string representation
     */
    std::string serialize() const;

    /**
     * @brief Deserialize a string to create a MaCpAbeClient object
     * @param data Serialized string data
     * @return Deserialized MaCpAbeClient object
     */
    static MaCpAbeDecryptor deserialize(const std::string &data,
                                        GlobalParameter &gp);

    /**
     * @brief Evaluate if an access policy can be satisfied
     *
     * Recursively evaluates whether the decryptor's attributes satisfy the
     * given access policy tree node and its children. Uses threshold gates
     * (k-of-n) for internal nodes and attribute matching for leaf nodes.
     *
     * @param node Current node in the access policy tree to evaluate
     * @return int Returns 1 if policy is satisfied, 0 otherwise
     */
    int evaluatePolicy(const std::shared_ptr<AccessPolicy::Node> &node);
    int evaluatePolicy(const AccessPolicy &AC);

    /**
     * @brief Prints all Client elements for debug purposes
     */
    void printClient() const;

  protected:
    /**
     * @brief Decrypt a node in the access policy tree
     *
     * Performs the actual decryption operation for a single node in the access
     * policy tree. For non-leaf nodes, it performs Lagrange interpolation on
     * the results of child nodes. For leaf nodes, it uses the attribute keys
     * to perform pairing-based decryption.
     *
     * @param GP Global parameters for cryptographic operations
     * @param node Current node in the access policy tree
     * @param keys Map of attribute keys for decryption
     * @param result Output parameter for the decryption result
     * @param share_tree Share tree node for caching results
     * @param is_stockable Flag indicating if intermediate results should be
     * cached
     */
    void decryptNode(const std::shared_ptr<AccessPolicy::Node> &node,
                     const client_key_map_t keys, element_t &result,
                     const std::shared_ptr<ShareTree> &share_tree,
                     bool is_stockable, bool lewko_mode = false,
                     bool optimized = false);

    /**
     * @brief Initialize the gid_hash based on the GID
     *
     * This method precomputes the hash of the GID and stores it in the gid_hash
     * buffer for later use in decryption operations.
     */
    void init_gid_hash();
};

#endif // MACPABE_DECRYPTOR_HPP
