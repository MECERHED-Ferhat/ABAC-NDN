#include <ABAC-NDN/Consumer.hpp>
#include <vector>
#include <string>
#include <iostream>

// g++ -std=c++17 Consumer.cpp -I. -I./utils $(pkg-config --cflags libndn-cxx) -L/usr/local/lib -lABAC-NDN -lndn-cxx -lpbc -lgmp -lcryptopp $(pkg-config --libs libndn-cxx) -o ndn_consumer_app && ./ndn_consumer_app

int main() {
    try {
        std::vector<std::string> consumerAttributes = {"Attr1", "Attr2", "Attr3", "Attr4", "Attr5", "Attr6", "Attr7", "Attr8"};
        std::cout << "Consumer : Lancement" << std::endl;
        consumeEncryptedStream(consumerAttributes, "/Domain");
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "ERREUR: " << e.what() << std::endl;
        return 1;
    }
}