#ifndef MACPABE_ENCRYPTOR_HPP
#define MACPABE_ENCRYPTOR_HPP

#include "AccessPolicy.h"
#include "Client.h"
#include "Polynome.h"
#include <algorithm>
#include <string>
#ifdef ESP32
#include "esp_heap_caps.h"
#endif

/**
 * @brief Encryptor class for CP-ABE encryption system
 *
 * This class handles the encryption of data according to access policies and
 * manages attribute-based encryption operations from the encryptor's
 * perspective. It extends the MaCpAbeClient class and provides methods for
 * encrypting data using CP-ABE policies.
 */
class MaCpAbeEncryptor : public MaCpAbeClient {
  public:
    unsigned char *egg_pairing_result =
        nullptr; ///< Pairing result (GT element)

    /**
     * @brief Construct a new Encryptor with a given global identifier
     * @param gid Global identifier string for the decryptor
     * @param gp Global parameters for cryptographic operations
     */
    explicit MaCpAbeEncryptor(const std::string &gid, GlobalParameter &gp);

    explicit MaCpAbeEncryptor(const MaCpAbeClient &client);

    /**
     * @brief Encrypt data into an attribute-based access policy
     *
     * @param M Message element to be encrypted (in GT group)
     * @param AC Access policy structure defining attribute-based rules and
     * stores the resulting ciphertext
     * @param pks Public key set containing attribute-based encryption keys
     * @param revoked_attrs List of attributes that have been revoked
     * @return bool True if encryption succeeded, false otherwise
     */
    bool encrypt(element_t &M, AccessPolicy &AC, const public_key_map_t &pks,
                 const std::vector<attribute_t> &revoked_attrs,
                 bool lewko_mode = false, bool optimized = false);

    static void deserializePublicKey(const std::string &input, 
                                        public_key_map_t &public_keys);

  protected:
    /**
     * @brief Fill the access policy tree with encryption values
     *
     * @param node Current node in the access policy tree
     * @param lambda Secret sharing parameter lambda
     * @param omega Secret sharing parameter omega
     * @param pks Public key set for attribute-based encryption
     * @param past_attrs Vector storing previously processed attributes
     * @param share_tree Current node in the share tree structure
     * @param is_stockable Flag indicating if values should be stored
     *
     * Recursively traverses the access policy tree and computes encryption
     * components for each node. For leaf nodes, it creates the ciphertext
     * components C1, C2, C3. For interior nodes, it performs secret sharing
     * according to the threshold policy.
     */
    bool fillPolicy(const std::shared_ptr<AccessPolicy::Node> &node,
                    element_t &lambda, element_t &omega,
                    const public_key_map_t &pks,
                    std::vector<attribute_t> &past_attrs,
                    const std::shared_ptr<ShareTree> &share_tree,
                    bool is_stockable, bool lewko_mode = false,
                    bool optimized = false);

    /**
     * @brief Update the access policy tree for revoked attributes
     *
     * @param node Current node in the access policy tree
     * @param revoked_attrs List of attributes that have been revoked
     * @param lambda Secret sharing parameter lambda
     * @param omega Secret sharing parameter omega
     * @param pks Public key set for attribute-based encryption
     * @param share_tree Current node in the share tree structure
     * @param is_stockable Flag indicating if values should be stored
     *
     * Updates the encryption components in the access policy tree when
     * attributes are revoked. It recomputes affected components while
     * maintaining the security of the encryption scheme. For AND/OR gates, it
     * applies special handling to maintain policy satisfaction.
     */
    void updatePolicy(const std::shared_ptr<AccessPolicy::Node> &node,
                      const std::vector<attribute_t> &revoked_attrs,
                      element_t &lambda, element_t &omega,
                      const public_key_map_t &pks,
                      const std::shared_ptr<ShareTree> &share_tree,
                      bool is_stockable, bool optimized = false);

    /**
     * @brief Initialize the egg pairing result
     * This method precomputes the pairing of the generator with itself and
     * stores the result in the egg pairing_result buffer.
     */
    void initEggPairingResult();
};

#endif // MACPABE_ENCRYPTOR_HPP
