#include "Global.h"

// Global variables & types
std::unordered_map<std::string, int> BUFFER_SIZE;

// Utility functions
void convertToByte(element_t &elt, std::vector<unsigned char *> &buffer,
                   const int position, const int ARRAY_SIZE) {
    // Create at the end
    if (position == -1) {
        buffer.push_back(new unsigned char[ARRAY_SIZE]);
        element_to_bytes(buffer.back(), elt);
    } else {
        element_to_bytes(buffer[position], elt);
    }
}
