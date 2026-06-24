#pragma once

#include "Global.h"

class Authority {
  public:
    std::string GID;              ///< Global identifier for the authority
    master_key_map_t master_keys; ///< Master keys per attribute
    raw_pk_map_t raw_public_keys;
    public_key_map_t public_keys;        ///< public key for each attribute
    std::vector<attribute_t> attributes; ///< List of attributes
    GlobalParameter GP;

    /// @brief Managed clients with attributes and updates
    /// @details Each client has a list of attributes and a list of updates
    ///          for each attribute. The updates are stored as a vector of
    ///          client_update_s structures.
    /// @note The client ID is a string, and the attribute is an attribute_t
    ///       (std::string).
    /// @note The client_update_s structure contains the gamma and random
    ///       factor for the update.
    /// @note The managed_clients map is a nested unordered_map, where the
    ///       outer map is keyed by client ID and the inner map is keyed by
    ///       attribute. The inner map contains a vector of client_update_s
    ///       structures, representing the updates for that attribute.
    typedef std::unordered_map<
        std::string,                                      // client_id
        std::unordered_map<attribute_t,                   // attribute
                           std::vector<client_update_s>>> // list of updates
        managed_clients_t;
    managed_clients_t managed_clients;

    /// @brief List of delta and t values for each attribute
    /// @details delta and t are stored as unsigned char* arrays
    ///          for each attribute.
    /// @note The delta and t values are stored in an unordered_map, where
    ///       the key is the attribute and the value is an unsigned char*
    ///       array representing the delta and t values for that attribute.
    typedef std::unordered_map<attribute_t, unsigned char *> attr_value_map_t;
    attr_value_map_t delta_list, t_list;

    /// @brief List of L_i and beta_i values for each client
    /// @details L_i and beta_i are stored as unsigned char* arrays
    ///          for each attribute and client ID.
    /// @note The L_i and beta_i values are stored in a nested unordered_map,
    ///       where the outer map is keyed by attribute and the inner map is
    ///       keyed by client ID. The inner map contains unsigned char* arrays
    ///       representing the L_i and beta_i values for that client.
    typedef std::unordered_map<attribute_t,
                               std::unordered_map<std::string, unsigned char *>>
        attr_client_value_map_t;
    attr_client_value_map_t L_list, beta_list;

    Authority(const std::string &gid);
    Authority() = default;

    /**
     * @brief Initializes the global pairing parameters for the cryptographic system.
     * 
     * This function reads the pairing parameters from a predefined file (../a.param),
     * sets up the pairing, and initializes the generator element. It also calculates
     * and stores the buffer sizes for G1, GT, and Zr elements.
     * 
     * @param GP Reference to the GlobalParameter object that will be initialized.
     * 
     * @throws std::runtime_error If the parameter file cannot be opened.
     * @throws pbc_die If the pairing parameters are invalid or not symmetric.
     */
    static void SetupGlobalParameter(GlobalParameter &GP);
    static void SetupGlobalParameterMedium(GlobalParameter &GP);
    static void SetupGlobalParameterHigh(GlobalParameter &GP);

    /**
     * @brief Sets up an Authority object with its master keys and public keys for a given set of attributes.
     * 
     * This function assigns the global parameters to the authority and generates
     * the master key and public key for each attribute provided. 
     * It is meant to quickly initialize an authority for testing or deployment.
     * 
     * @param GP Reference to the previously initialized GlobalParameter object.
     * @param auth Reference to the Authority object to be set up.
     * @param attributes Vector of attribute names (strings) to generate keys for.
     */
    static void SetupAuthority(GlobalParameter &GP, Authority &auth, const std::vector<std::string> &attributes);



    /**
     * @brief Generate master key for a given attribute
     * @param attr The attribute for which to generate the master key
     * @details This function generates a master key for the specified
     *          attribute and stores it in the master_keys map.
     *          This is part of the key generation process for the
     *          authority in a multi-authority ciphertext-policy attribute-based
     *          encryption (MA-CP-ABE) system.
     */
    void generateMasterKey(const attribute_t attr);

    /**
     * @brief Generate public key for a given attribute
     * @param attr The attribute for which to generate the public key
     * @param update If true, updates the public key to version 0
     * @details This function generates a raw public key for the specified
     *          attribute using the master key and stores it in the
     *          raw_public_keys map. And after that, if the update parameter
     *          is true it calls automatically the updatePublicKey method to
     *          generate a public key version 0.
     *          This is part of the key generation process for the authority in
     *          a multi-authority ciphertext-policy attribute-based encryption
     *          (MA-CP-ABE) system.
     */
    void generatePublicKey(const attribute_t attr);

    /**
     * @brief Update public key for a given attribute to a new version
     * @param attr The attribute for which to update the public key
     * @details This function generates a raw public key for the specified
     *          attribute using the master key and stores it in the
     *          raw_public_keys map. This is part of the key generation
     *          process for the authority in a multi-authority
     *          ciphertext-policy attribute-based encryption (MA-CP-ABE) system.
     */
    void updatePublicKey(const attribute_t attr);

    std::string serializePublicKey(const attribute_t &attr);

    /**
     * @brief Store raw public keys directly in the public keys map
     * @param attr The attribute for which to store the raw public keys
     * @details This function stores the raw public keys directly in the
     *          public_keys map, bypassing updatePublicKey.
     *          This is useful for evaluation against Lewko's scheme.
     */
    void storeRawPublicKeysDirectly(const attribute_t attr);

    /**
     * @brief Generate a client key for a given client and attribute
     * @param clientId The ID of the client
     * @param attr The attribute for which to generate the client key
     * @param tmp_key Temporary buffer to store the generated key
     * @param tmp_L Temporary buffer to store the L_i value
     * @param lewko_mode If true, uses Lewko's mode for key generation (don't
     *                   versioning the client keys with updates)
     * @details The client key consists of a key and an L_i value, and must be
     *          transmitted to the client securely.
     */
    std::string generateClientKey(const std::string &clientId, const attribute_t attr);

    /**
     * @brief Serialize client parameters for a transfer through a secure
     *        channel
     * @param gid Global identifier for the client
     * @param attributes List of attributes
     * @param keys List of keys
     * @param l_i List of L_i values
     * @return Serialized string representation
     */
    static std::string
    storeClientKeys(const std::string &gid,
                    const std::string &attribute,
                    const unsigned char *key,
                    const unsigned char *l_i);

    void deleteClientAttribute(const std::string &clientId,
                               const attribute_t &attr);
    void deleteClient(const std::string &clientId);

    bool hasAttribute(const attribute_t attr);
    bool hasClient(const std::string &clientId);
    bool hasClientAttribute(const std::string &clientId,
                            const attribute_t &attr);

    /**
     * @brief Generate an update for a client with a given attribute
     * @param clientId The ID of the client
     * @param attr The attribute for which to generate the update
     * @param tmp_gamma Temporary buffer to store the gamma value
     * @param tmp_random Temporary buffer to store the random factor
     * @details The update consists of a gamma value and a random factor.
     */
    std::string generateClientUpdate(GlobalParameter &GP, 
                                    const std::string &clientId,
                                    const attribute_t attr);


    void revokeAttribute(const std::string &clientId,
                                const attribute_t &attr);

    /**
     * @brief Store a client update in the managed_clients map
     * @param clientId The ID of the client
     * @param attr The attribute for which to store the update
     * @param gamma Pointer to the gamma value
     * @param random Pointer to the random factor
     * @details This function stores the update in the managed_clients map
     *          under the specified client ID and attribute. If the client or
     *          attribute does not exist, it will be created.
     */
    void storeClientUpdate(const std::string &clientId, const attribute_t &attr,
                           unsigned char *gamma, unsigned char *random);
    uint32_t getClientUpdate(const std::string &clientId,
                             const attribute_t &attr, client_update_s *&update,
                             uint32_t version);

    /**
     * @brief Print the authority state (with all private keys!)
     * @details This function prints the authority ID, attributes, master keys,
     *          public keys, and managed clients with their updates.
     */
    void print() const;

    /// @brief Save authority state to a text file
    /// @param filename The name of the file to save
    /// @return true if saving was successful, false otherwise
    /// @details The file will contain the authority ID, attributes, master
    ///          keys, public keys, and managed clients with their updates.
    /// @note The file does not include the global parameters (GP).
    bool saveAuthorityState(const std::string &filename);

    /// @brief Load authority state from a file and overwrite the given
    ///        authority object
    /// @param filename The name of the file to load
    /// @param GP Global parameters for the authority
    /// @param resultAuth The Authority object to populate
    /// @return true if loading was successful, false otherwise
    /// @details The file should be created by the saveAuthorityState
    static bool loadAuthorityState(const std::string &filename,
                                   GlobalParameter &GP, Authority &resultAuth);

    static std::vector<uint8_t> serializeGlobalParameter(GlobalParameter& gp);
};
