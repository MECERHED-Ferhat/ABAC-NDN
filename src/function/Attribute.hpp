/**
 * @file Attribute.hpp
 * @brief An idea of an Attribute class and ClientAttribute class but is not used
 */

#pragma once

#include <string>
#include <vector>

class Attribute {
  public:
    Attribute(const std::string &authority, const std::string &attribute, int ver)
        : authorityId(authority), attributeName(attribute), version(ver) {}

    bool operator==(const Attribute &other) const {
        return authorityId == other.authorityId &&
               attributeName == other.attributeName && version == other.version;
    }

    std::string authorityId;
    std::string attributeName;
    int version;
};

namespace std {
template <> struct hash<Attribute> {
    std::size_t operator()(const Attribute &attr) const {
        return std::hash<std::string>()(attr.authorityId) ^
               std::hash<std::string>()(attr.attributeName) ^
               std::hash<int>()(attr.version);
    }
};

class ClientAttribute : public Attribute {
  public:
    ClientAttribute(const std::string &authority, const std::string &attribute, int ver)
        : Attribute(authority, attribute, ver), clientKey(nullptr), clientLi(nullptr), clientKeyFinal(nullptr) {}

    unsigned char *getClientKey() const { return clientKey; }
    unsigned char *getClientLi() const { return clientLi; }
    unsigned char *getClientKeyFinal() const { return clientKeyFinal; }
    const std::vector<unsigned char *> &getClientUpdate() const { return clientUpdate; }

    void setClientKeyAndLi(unsigned char *key, unsigned char *li) {
        clientKey = key;
        clientLi = li;
    }

    void setClientKeyFinal(unsigned char *keyFinal) {
        clientKeyFinal = keyFinal;
    }

    void setClientUpdate(const std::vector<unsigned char *> &update) {
        clientUpdate = update;
    }

  private:
    unsigned char *clientKey;
    unsigned char *clientLi;
    unsigned char *clientKeyFinal;
    std::vector<unsigned char *> clientUpdate;
};
} // namespace std