#include <ABAC-NDN/Authority.hpp>
#include <vector>
#include <string>
#include <iostream>

// g++ -std=c++17 Authority.cpp -I. -I./utils $(pkg-config --cflags libndn-cxx) -L/usr/local/lib -lABAC-NDN -lndn-cxx -lpbc -lgmp -lcryptopp $(pkg-config --libs libndn-cxx) -o ndn_authority_app && ./ndn_authority_app

int main() {
    try {
        std::string authorityName = "authority";
        std::string decryptorID = "decryptor";
        std::vector<std::string> authority_attributes = {"Attr1", "Attr2", "Attr3", "Attr4", "Attr5", "Attr6", "Attr7", "Attr8"};
        std::cout << "Authority : Lancement" << std::endl;
        int ret = runNDNAuthority(authorityName, decryptorID, authority_attributes);
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "ERREUR: " << e.what() << std::endl;
        return 1;
    }
}
