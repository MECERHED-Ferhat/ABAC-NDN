#include "AccessPolicy.h"
#include "utils.hpp"

#include <cstring>
#include <iostream>

AccessPolicy::Node::Node(const attribute_t &attribute, int k, int n)
    : attribute(attribute), k(k), n(n), c1(nullptr), c2(nullptr), c3(nullptr) {
    is_leaf = (n == 0);
    if (is_leaf) {
        children = {};
        c1 = new unsigned char[BUFFER_SIZE["GT"]];
        std::memset(c1, 0, BUFFER_SIZE["GT"]);
        c2 = new unsigned char[BUFFER_SIZE["G1"]];
        std::memset(c2, 0, BUFFER_SIZE["G1"]);
        c3 = new unsigned char[BUFFER_SIZE["G1"]];
        std::memset(c3, 0, BUFFER_SIZE["G1"]);
    } else
        children.reserve(n);
    // std::string out = is_leaf ? attribute : std::to_string(k) + "/" +
    //                   std::to_string(n);
    // std::cout << "Node created: " << out << std::endl;
}


// Node destructor to clean up allocated memory
AccessPolicy::Node::~Node() {
    delete[] c1;
    delete[] c2;
    delete[] c3;
    c1 = nullptr;
    c2 = nullptr;
    c3 = nullptr;
}

void AccessPolicy::Node::print(GlobalParameter &GP, int depth = 0) const {
    std::cout << "is_modified: " << is_modified << std::endl;

    // Print satisfied_node_index
    std::cout << "_satisfied_node_index: [";
    for (size_t i = 0; i < _satisfied_node_index.size(); ++i) {
        std::cout << _satisfied_node_index[i];
        if (i + 1 < _satisfied_node_index.size()) std::cout << ", ";
    }
    std::cout << "]\n";

    // Print coming attributes
    std::cout << "_coming_attrs: [";
    for (size_t i = 0; i < _coming_attrs.size(); ++i) {
        std::cout << _coming_attrs[i];
        if (i + 1 < _coming_attrs.size()) std::cout << ", ";
    }
    std::cout << "]\n";

    if (is_leaf) {
        element_t tmpc1, tmpc2, tmpc3;
        element_init_GT(tmpc1, GP.e);
        element_from_bytes(tmpc1, c1);
        element_init_G1(tmpc2, GP.e);
        element_from_bytes(tmpc2, c2);
        element_init_G1(tmpc3, GP.e);
        element_from_bytes(tmpc3, c3);

        for (int i = 0; i < depth; ++i)
            std::cout << "  ";
        std::cout << "Leaf: " << attribute;
        element_printf(" | c1=%B | c2=%B | c3=%B \n", tmpc1, tmpc2, tmpc3);

        element_clear(tmpc1);
        element_clear(tmpc2);
        element_clear(tmpc3);
    } else {
        for (int i = 0; i < depth; ++i)
            std::cout << "  ";
        std::cout << "Threshold: " << k << "/" << n << std::endl;
        for (const auto &child : children) {
            child->print(GP, depth + 1);
        }
    }
}

void AccessPolicy::Node::addChild(std::shared_ptr<Node> child) {
    if (children.size() < n) {
        children.push_back(child);
    } else {
        throw std::runtime_error("Cannot add more children than n");
    }
}

void AccessPolicy::Node::serializeNode(std::ostream &os, const AccessPolicy::Node &node) {
    // Booleans
    os.write(reinterpret_cast<const char*>(&node.is_modified), sizeof(node.is_modified));
    os.write(reinterpret_cast<const char*>(&node.is_leaf), sizeof(node.is_leaf));

    // Vectors<int>
    size_t size_vec = node._satisfied_node_index.size();
    os.write(reinterpret_cast<const char*>(&size_vec), sizeof(size_vec));
    for (int val : node._satisfied_node_index) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    }

    // Vectors<string>
    size_t str_vec_size = node._coming_attrs.size();
    os.write(reinterpret_cast<const char*>(&str_vec_size), sizeof(str_vec_size));
    for (const auto &s : node._coming_attrs) {
        size_t len = s.size();
        os.write(reinterpret_cast<const char*>(&len), sizeof(len));
        os.write(s.data(), len);
    }

    // ints k, n
    os.write(reinterpret_cast<const char*>(&node.k), sizeof(node.k));
    os.write(reinterpret_cast<const char*>(&node.n), sizeof(node.n));

    // attribute string
    size_t attr_len = node.attribute.size();
    os.write(reinterpret_cast<const char*>(&attr_len), sizeof(attr_len));
    os.write(node.attribute.data(), attr_len);

    // Buffers only if leaf
    if (node.is_leaf) {
        os.write(reinterpret_cast<const char*>(node.c1), BUFFER_SIZE["GT"]);
        os.write(reinterpret_cast<const char*>(node.c2), BUFFER_SIZE["G1"]);
        os.write(reinterpret_cast<const char*>(node.c3), BUFFER_SIZE["G1"]);
    }
}

std::shared_ptr<AccessPolicy::Node> AccessPolicy::Node::deserializeNode(std::istream &is) {
    bool is_modified, is_leaf;

    // Read booleans
    is.read(reinterpret_cast<char*>(&is_modified), sizeof(is_modified));
    is.read(reinterpret_cast<char*>(&is_leaf), sizeof(is_leaf));

    // Read satisfied_node_index
    size_t size_vec;
    is.read(reinterpret_cast<char*>(&size_vec), sizeof(size_vec));
    std::vector<int> satisfied(size_vec);
    for (size_t i = 0; i < size_vec; i++) {
        is.read(reinterpret_cast<char*>(&satisfied[i]), sizeof(int));
    }

    // Read coming_attrs
    size_t str_vec_size;
    is.read(reinterpret_cast<char*>(&str_vec_size), sizeof(str_vec_size));
    std::vector<std::string> coming(str_vec_size);
    for (size_t i = 0; i < str_vec_size; i++) {
        size_t len;
        is.read(reinterpret_cast<char*>(&len), sizeof(len));
        coming[i].resize(len);
        is.read(&coming[i][0], len);
    }

    // Read k, n
    int k, n;
    is.read(reinterpret_cast<char*>(&k), sizeof(k));
    is.read(reinterpret_cast<char*>(&n), sizeof(n));

    // Read attribute
    size_t attr_len;
    is.read(reinterpret_cast<char*>(&attr_len), sizeof(attr_len));
    std::string attr(attr_len, '\0');
    is.read(&attr[0], attr_len);

    // Construct Node
    auto node = std::make_shared<AccessPolicy::Node>(attr, k, n);
    node->is_modified = is_modified;
    node->is_leaf = is_leaf;
    node->_satisfied_node_index = std::move(satisfied);
    node->_coming_attrs = std::move(coming);

    // Read buffers if leaf
    if (is_leaf) {
        is.read(reinterpret_cast<char*>(node->c1), BUFFER_SIZE["GT"]);
        is.read(reinterpret_cast<char*>(node->c2), BUFFER_SIZE["G1"]);
        is.read(reinterpret_cast<char*>(node->c3), BUFFER_SIZE["G1"]);
    }

    return node;
}

void AccessPolicy::Node::serializeTree(std::ostream &os, const std::shared_ptr<Node> &root) {
    if (!root) {
        // Mark a null node
        bool hasNode = false;
        os.write(reinterpret_cast<const char*>(&hasNode), sizeof(hasNode));
        return;
    }

    bool hasNode = true;
    os.write(reinterpret_cast<const char*>(&hasNode), sizeof(hasNode));

    // Serialize this node's data
    serializeNode(os, *root);

    // Serialize number of children
    size_t numChildren = root->children.size();
    os.write(reinterpret_cast<const char*>(&numChildren), sizeof(numChildren));

    // Recurse into children
    for (const auto &child : root->children) {
        serializeTree(os, child);
    }
}

std::shared_ptr<AccessPolicy::Node> AccessPolicy::Node::deserializeTree(std::istream &is) {
    bool hasNode;
    is.read(reinterpret_cast<char*>(&hasNode), sizeof(hasNode));
    if (!hasNode) {
        return nullptr;
    }

    // Deserialize the node itself
    auto node = deserializeNode(is);

    // Read children count
    size_t numChildren;
    is.read(reinterpret_cast<char*>(&numChildren), sizeof(numChildren));

    // Recurse for each child
    for (size_t i = 0; i < numChildren; i++) {
        auto child = deserializeTree(is);
        if (child) {
            node->addChild(child);
        }
    }

    return node;
}


AccessPolicy::AccessPolicy() : root(nullptr) {
    c0 = new unsigned char[BUFFER_SIZE["GT"]];
    std::memset(c0, 0, BUFFER_SIZE["GT"]); // Initialisiere mit Nullen
}

// Copy-Konstruktor hinzufügen
AccessPolicy::AccessPolicy(const AccessPolicy &other)
    : root(other.root), policyString(other.policyString),
      leaf_attributes(other.leaf_attributes) {
    c0 = new unsigned char[BUFFER_SIZE["GT"]];
    if (other.c0) {
        std::memcpy(c0, other.c0, BUFFER_SIZE["GT"]);
    } else {
        std::memset(c0, 0, BUFFER_SIZE["GT"]);
    }
}

// Move-Konstruktor hinzufügen
AccessPolicy::AccessPolicy(AccessPolicy &&other) noexcept
    : root(std::move(other.root)), policyString(std::move(other.policyString)),
      leaf_attributes(std::move(other.leaf_attributes)), c0(other.c0) {
    // Wichtig: Setze den Zeiger auf null, damit er nicht doppelt gelöscht wird
    other.c0 = nullptr;
}

// Zuweisungsoperator hinzufügen
AccessPolicy &AccessPolicy::operator=(const AccessPolicy &other) {
    if (this != &other) {
        root = other.root;
        policyString = other.policyString;
        leaf_attributes = other.leaf_attributes;

        // Kopiere c0
        if (other.c0) {
            if (!c0) {
                c0 = new unsigned char[BUFFER_SIZE["GT"]];
            }
            std::memcpy(c0, other.c0, BUFFER_SIZE["GT"]);
        } else {
            // Wenn other.c0 null ist, setzen wir unseren Wert auch auf null
            if (c0) {
                delete[] c0;
                c0 = nullptr;
            }
        }
    }
    return *this;
}

// Move-Zuweisungsoperator hinzufügen
AccessPolicy &AccessPolicy::operator=(AccessPolicy &&other) noexcept {
    if (this != &other) {
        // Speicher freigeben
        if (c0) {
            delete[] c0;
        }

        // Übernehme Ressourcen
        root = std::move(other.root);
        policyString = std::move(other.policyString);
        leaf_attributes = std::move(other.leaf_attributes);
        c0 = other.c0;

        // Wichtig: Setze den Zeiger auf null, damit er nicht doppelt gelöscht
        // wird
        other.c0 = nullptr;
    }
    return *this;
}

// Korrigierter Destruktor
AccessPolicy::~AccessPolicy() {
    delete[] c0;  // Keine Prüfung nötig, delete[] auf nullptr ist sicher
    c0 = nullptr; // Setze den Zeiger auf null, um Double-Free zu vermeiden
}

void AccessPolicy::setPolicy(const std::string &policyStr) {
    // Remove any whitespace characters from the policy string
    std::string result;
    for (char c : policyStr) {
        if (!std::isspace(c)) {
            result += c;
        }
    }

    policyString = result;
    leaf_attributes.clear();
    root = newFromString(policyString, leaf_attributes);
}

void AccessPolicy::setPolicy(std::shared_ptr<Node> newRoot) {
    root = newRoot;
    policyString = AccessPolicy::getStringRepresentationFromNodeTree(root);
}

std::string AccessPolicy::getPolicyString() const { return policyString; }

const std::vector<attribute_t> AccessPolicy::getLeafAttributes() const {
    return leaf_attributes;
}

std::string AccessPolicy::getStringRepresentationFromNodeTree(
    const std::shared_ptr<AccessPolicy::Node> &node) {
    if (node->is_leaf)
        return node->attribute;
    std::string result =
        std::to_string(node->k) + "/" + std::to_string(node->n) + "(";
    for (size_t i = 0; i < node->children.size(); ++i) {
        result += AccessPolicy::getStringRepresentationFromNodeTree(
            node->children[i]);
        if (i < node->children.size() - 1) {
            result += ",";
        }
    }
    result += ")";
    return result;
}

// This function validates, that the policy string matches the Node Tree
// structure
bool AccessPolicy::validatePolicyStringMatch() {
    if (!root) {
        return false; // No root means no policy
    }
    return policyString ==
           AccessPolicy::getStringRepresentationFromNodeTree(root);
}

void AccessPolicy::print(GlobalParameter &GP) const {
    std::cout << "policyString: " << policyString << std::endl;

    // Print satisfied_node_index
    std::cout << "leaf_attributes [";
    for (size_t i = 0; i < leaf_attributes.size(); ++i) {
        std::cout << leaf_attributes[i];
        if (i + 1 < leaf_attributes.size()) std::cout << ", ";
    }
    std::cout << "]\n";
    
    if (root) {
        std::cout << "AccessPolicy tree:" << std::endl;
        element_t tmpc0;
        element_init_GT(tmpc0, GP.e);
        element_from_bytes(tmpc0, c0);
        element_printf("AccessPolicy c0: %B\n", tmpc0);
        element_clear(tmpc0);
        root->print(GP);
    } else {
        std::cout << "Empty AccessPolicy tree." << std::endl;
    }
}

std::shared_ptr<AccessPolicy::Node>
AccessPolicy::newFromString(const std::string &str,
                            std::vector<attribute_t> &leaf_attributes) {
    if (str.empty()) {
        return nullptr;
    }

    // std::cout << "Parsing policy string: " << str << std::endl;

    // if the string is a single attribute, create a leaf node and return
    if (isalpha(str[0])) {
        bool isValidAttribute = true;
        for (size_t i = 1; i < str.length(); i++) {
            if (!isalnum(str[i])) {
                isValidAttribute = false;
                break;
            }
        }

        if (isValidAttribute) {
            leaf_attributes.push_back(str);
            return std::make_shared<AccessPolicy::Node>(str, 0, 0);
        }

        throw std::invalid_argument("Invalid attribute name: " + str);
    }

    // parsing threshold
    size_t slashPos = str.find('/');
    size_t openParenPos = str.find('(');

    if (slashPos == std::string::npos || openParenPos == std::string::npos ||
        openParenPos <= slashPos) {
        throw std::invalid_argument("Invalid threshold format: " + str);
    }

    int k = std::stoi(str.substr(0, slashPos));
    int n = std::stoi(str.substr(slashPos + 1, openParenPos - slashPos - 1));

    // find closing parenthesis
    if (str.back() != ')') {
        throw std::invalid_argument("Missing closing parenthesis: " + str);
    }

    // extract children string
    std::string childrenStr =
        str.substr(openParenPos + 1, str.length() - openParenPos - 2);

    auto threshold = std::make_shared<AccessPolicy::Node>("", k, n);

    // recursive child parsing
    size_t startPos = 0;
    int openBrackets = 0;

    for (size_t i = 0; i < childrenStr.length(); i++) {
        char c = childrenStr[i];
        if (c == '(') {
            openBrackets++;
        } else if (c == ')') {
            openBrackets--;
        } else if (c == ',' && openBrackets == 0) {
            // we found a complete child
            std::string childStr = childrenStr.substr(startPos, i - startPos);
            threshold->addChild(newFromString(childStr, leaf_attributes));
            startPos = i + 1;
        }
    }

    // add the last child if there is any remaining string
    std::string lastChild = childrenStr.substr(startPos);
    if (!lastChild.empty()) {
        threshold->addChild(newFromString(lastChild, leaf_attributes));
    }

    return threshold;
}

void AccessPolicy::resetIsModifiedField(
    std::shared_ptr<AccessPolicy::Node> node, bool to) {
    node->is_modified = to;
    for (int i = 0; i < node->children.size(); i++) {
        resetIsModifiedField(node->children[i]);
    }
}

void AccessPolicy::serializeAC(std::ostream &os, const AccessPolicy &ac) {
    // 1. Serialize root tree
    Node::serializeTree(os, ac.root);

    // 2. Serialize leaf_attributes
    size_t vecSize = ac.leaf_attributes.size();
    os.write(reinterpret_cast<const char*>(&vecSize), sizeof(vecSize));
    for (const auto &s : ac.leaf_attributes) {
        size_t len = s.size();
        os.write(reinterpret_cast<const char*>(&len), sizeof(len));
        os.write(s.data(), len);
    }

    // 3. Serialize policyString
    size_t policyLen = ac.policyString.size();
    os.write(reinterpret_cast<const char*>(&policyLen), sizeof(policyLen));
    os.write(ac.policyString.data(), policyLen);

    // 4. Serialize c0 buffer
    os.write(reinterpret_cast<const char*>(ac.c0), BUFFER_SIZE["GT"]);
}

std::shared_ptr<AccessPolicy> AccessPolicy::deserializeAC(std::istream &is) {
    auto ac = std::make_shared<AccessPolicy>();

    // 1. Deserialize root tree
    ac->root = Node::deserializeTree(is);

    // 2. Deserialize leaf_attributes
    size_t vecSize;
    is.read(reinterpret_cast<char*>(&vecSize), sizeof(vecSize));
    ac->leaf_attributes.resize(vecSize);
    for (size_t i = 0; i < vecSize; i++) {
        size_t len;
        is.read(reinterpret_cast<char*>(&len), sizeof(len));
        ac->leaf_attributes[i].resize(len);
        is.read(&ac->leaf_attributes[i][0], len);
    }

    // 3. Deserialize policyString
    size_t policyLen;
    is.read(reinterpret_cast<char*>(&policyLen), sizeof(policyLen));
    ac->policyString.resize(policyLen);
    is.read(&ac->policyString[0], policyLen);

    // 4. Deserialize c0 buffer
    ac->c0 = new unsigned char[BUFFER_SIZE["GT"]];
    is.read(reinterpret_cast<char*>(ac->c0), BUFFER_SIZE["GT"]);

    return ac;
}
