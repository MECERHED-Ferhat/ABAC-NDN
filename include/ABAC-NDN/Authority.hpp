#ifndef NDN_AUTHORITY
#define NDN_AUTHORITY

#include <string>
#include <vector>

int runNDNAuthority(
    const std::string& authorityName,
    const std::string& decryptorID,
    const std::vector<std::string>& attributes);

#endif
