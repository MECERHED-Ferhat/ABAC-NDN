#include <ABAC-NDN/Producer.hpp>
#include <vector>
#include <string>
#include <iostream>

// g++ -std=c++17 Producer.cpp -I. -I./utils $(pkg-config --cflags libndn-cxx) -L/usr/local/lib -lABAC-NDN -lndn-cxx -lpbc -lgmp -lcryptopp $(pkg-config --libs libndn-cxx) -o ndn_producer_app && ./ndn_producer_app

int main() {
    try {
        std::vector<std::string> producerAttributes = {"Attr1", "Attr2", "Attr3", "Attr4", "Attr5", "Attr6", "Attr7", "Attr8"};
        std::cout << "Producer : Lancement" << std::endl;
        publishEncryptedStream(producerAttributes, "/Domain", "2/2(Attr1,Attr2)", "I'm here !!!");
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "ERREUR: " << e.what() << std::endl;
        return 1;
    }
}
