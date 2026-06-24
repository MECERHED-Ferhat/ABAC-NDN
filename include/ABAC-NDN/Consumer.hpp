#ifndef NDN_CONSUMER
#define NDN_CONSUMER

#include <string>
#include <vector>

int consumeEncryptedStream(
    const std::vector<std::string>& decryptor_attributes,
    const std::string tmp_prefix);

#endif