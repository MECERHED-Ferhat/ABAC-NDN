#ifndef NDN_PRODUCER
#define NDN_PRODUCER

#include <vector>
#include <string>

int publishEncryptedStream(
    const std::vector<std::string>& encryptor_attributes,
    const std::string tmp_prefix,
    const std::string tmp_acc_desc,
    const std::string tmp_data);

#endif
