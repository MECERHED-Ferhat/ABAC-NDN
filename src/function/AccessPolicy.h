#ifndef ACCESSPOLICY_H
#define ACCESSPOLICY_H

#include "Global.h"
#include <memory>

class AccessPolicy {
    friend class NdnPolicySerializer; // Allow NdnPolicySerializer to access
                                      // private members
    friend class AccessPolicySerializationTest; // Allow test class to access
                                                // private members

  public:
    class Node {
      public:
        bool is_leaf;
        bool is_modified = true;
        attribute_t attribute;
        int k;
        int n;
        std::vector<std::shared_ptr<Node>> children;
        unsigned char *c1;
        unsigned char *c2;
        unsigned char *c3;
        std::vector<int> _satisfied_node_index;
        std::vector<attribute_t> _coming_attrs;

        Node(const attribute_t &attribute, int k, int n);
        ~Node();

        void print(GlobalParameter &GP, int depth) const;
        void addChild(std::shared_ptr<Node> child);
        static void serializeNode(std::ostream &os, const AccessPolicy::Node &node);
        static std::shared_ptr<Node> deserializeNode(std::istream &is);
        static void serializeTree(std::ostream &os, const std::shared_ptr<Node> &root);
        static std::shared_ptr<AccessPolicy::Node> deserializeTree(std::istream &is);
    };

    // Class Access Policy
    std::shared_ptr<Node> root;
    std::vector<attribute_t> leaf_attributes;
    std::string policyString;
    unsigned char *c0;

    AccessPolicy();
    AccessPolicy(const AccessPolicy &other);
    AccessPolicy(AccessPolicy &&other) noexcept;
    AccessPolicy &operator=(const AccessPolicy &other);
    AccessPolicy &operator=(AccessPolicy &&other) noexcept;
    ~AccessPolicy();

    /**
     * Set the access policy from a string representation.
     * The string should be formatted according to the policy syntax.
     * Example: "1/2(a, b)" for a threshold policy with k=1, n=2 and attributes
     * a and b, or "a" for a leaf node.
     * @param policyStr The string representation of the access policy.
     * @throws std::runtime_error if the policy string is malformed.
     * @note a new tree and will be stored in the root node.
     */
    void setPolicy(const std::string &policyStr);

    /**
     * Set the access policy from a new root node.
     * @param newRoot The new root node of the access policy tree.
     * @note This will replace the current policy tree.
     * @throws std::runtime_error if the new root is null.
     * @note The policy string will be updated based on the new root.
     */
    void setPolicy(std::shared_ptr<Node> newRoot);

    void print(GlobalParameter &GP) const;
    const std::vector<attribute_t> getLeafAttributes() const;
    std::string getPolicyString() const;

    static std::string getStringRepresentationFromNodeTree(
        const std::shared_ptr<AccessPolicy::Node> &node);
    
    static std::shared_ptr<Node>
    newFromString(const std::string &str,
                  std::vector<attribute_t> &leaf_attributes);
    
    static void resetIsModifiedField(std::shared_ptr<Node> node, bool to = false);
    bool validatePolicyStringMatch();


    static void serializeAC(std::ostream &os, const AccessPolicy &ac);
    static std::shared_ptr<AccessPolicy> deserializeAC(std::istream &is);
};

#endif // ACCESSPOLICY_H