#include "ABAC-NDN/Authority.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include "AccessPolicy.h"
#include "Authority.h"
#include "Encryptor.h"
#include "Decryptor.h"
#include "Global.h"
#include "AESWrapper.h"
#include "utils.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cryptopp/aes.h>

// g++ -std=c++17 src/ndn_authority.cpp ma_cp_abe/*.cpp -I. -I./utils $(pkg-config --cflags libndn-cxx) -L/usr/local/lib -lpbc -lgmp -lcryptopp $(pkg-config --libs libndn-cxx) -o ndn_authority_app; export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH; ./ndn_authority_app


// Suppression of the global variable to put them in attributes of the different classes 

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Producer
{
public:
  // Constructor modified to receive required parameters
  Producer(Authority& auth,
           const std::string& decryptorID)
    : auth(auth)
    , decryptorID(decryptorID)
  {}

  void
  run()
  {
    m_face.setInterestFilter("/Domain/GlobalParameter",
                             std::bind(&Producer::onInterestGlobalParameter, this, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.setInterestFilter("/Domain/ClientKey",
                             std::bind(&Producer::onInterestClientKey, this, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.setInterestFilter("/Domain/Update",
                             std::bind(&Producer::onInterestUpdate, this, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.setInterestFilter("/Domain/PublicKey",
                             std::bind(&Producer::onInterestPublickey, this, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));

    auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
    m_certServeHandle = m_face.setInterestFilter(security::extractIdentityFromCertName(cert.getName()),
                                                 [this, cert] (auto&&...) {
                                                   m_face.put(cert);
                                                 },
                                                 std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterestGlobalParameter(const Interest& interest)
  {
      std::cout << ">> I: " << interest << std::endl;

      auto data = std::make_shared<Data>();
      data->setName(interest.getName());
      data->setFreshnessPeriod(10_s);

      std::vector<uint8_t> generator_serialized;
      generator_serialized = Authority::serializeGlobalParameter(auth.GP);
      data->setContent({generator_serialized.data(), generator_serialized.size()});

      // Sign Data packet (optional if you don't care about signature)
      m_keyChain.sign(*data);

      std::cout << "<< D: " << *data << std::endl;
      m_face.put(*data);
  }

  void
  onInterestClientKey(const Interest& interest)
  {
      std::cout << ">> I: " << interest << std::endl;

      // Extract attribute from Interest name (last component)
      auto interestName = interest.getName();
      if (interestName.size() < 3) { // /Domain/Update/<attr> → needs at least 3 components
          std::cerr << "Invalid Interest name: " << interestName << std::endl;
          return;
      }
      std::string attr = interestName[-1].toUri(); // last component is the attribute

      // Call generateClientUpdate
      std::string keyData = auth.generateClientKey(decryptorID, attr);

      // Create Data packet
      auto data = std::make_shared<Data>();
      data->setName(interestName);
      data->setFreshnessPeriod(10_s);

      // Put the update string into the content
      data->setContent(keyData);

      // Sign Data packet
      m_keyChain.sign(*data);

      std::cout << "<< D: " << *data << std::endl;
      m_face.put(*data);
  }

  void
  onInterestUpdate(const Interest& interest)
  {
      std::cout << ">> I: " << interest << std::endl;

      // Extract attribute from Interest name (last component)
      auto interestName = interest.getName();
      if (interestName.size() < 3) { // /Domain/Update/<attr> → needs at least 3 components
          std::cerr << "Invalid Interest name: " << interestName << std::endl;
          return;
      }
      std::string attr = interestName[-1].toUri(); // last component is the attribute

      // Call generateClientUpdate
      std::string updateData = auth.generateClientUpdate(auth.GP, decryptorID, attr);

      // Create Data packet
      auto data = std::make_shared<Data>();
      data->setName(interestName);
      data->setFreshnessPeriod(10_s);

      // Put the update string into the content
      data->setContent(updateData);

      // Sign Data packet
      m_keyChain.sign(*data);

      std::cout << "<< D: " << *data << std::endl;
      m_face.put(*data);
  }

  void
  onInterestPublickey(const Interest& interest)
  {
      std::cout << ">> I: " << interest << std::endl;

      // Extract attribute from Interest name (last component)
      auto interestName = interest.getName();
      if (interestName.size() < 3) { // /Domain/Update/<attr> → needs at least 3 components
          std::cerr << "Invalid Interest name: " << interestName << std::endl;
          return;
      }
      std::string attr = interestName[-1].toUri(); // last component is the attribute

      // Call generateClientUpdate
      std::string pk_str = auth.serializePublicKey(attr);
      std::cout << pk_str << std::endl;

      // Create Data packet
      auto data = std::make_shared<Data>();
      data->setName(interestName);
      data->setFreshnessPeriod(10_s);

      // Put the update string into the content
      data->setContent(pk_str);

      // Sign Data packet
      m_keyChain.sign(*data);

      std::cout << "<< D: " << *data << std::endl;
      m_face.put(*data);
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")\n";
    m_face.shutdown();
  }

private:
  Face m_face;
  KeyChain m_keyChain;
  ScopedRegisteredPrefixHandle m_certServeHandle;

  Authority& auth;
  std::string decryptorID;
};

} // namespace examples
} // namespace ndn


int runNDNAuthority(
    const std::string& authorityName,
    const std::string& decryptorID,
    const std::vector<std::string>& authority_attributes)
{
  std::cout << "Launching of the Authority Process" << std::endl;
  try {
    // Setup Authority
    Authority auth(authorityName);
    Authority::SetupGlobalParameter(auth.GP);
    Authority::SetupAuthority(auth.GP, auth, authority_attributes);

    // Setting up decryptor keys
    /*
    for (const auto& attr : {"Attr1", "Attr2"}) {
        std::ostringstream filename;
        filename << attr << "_key.txt";

        std::string str_key = auth.generateClientKey(decryptorID, attr);

        // Check if file already exists
        std::ifstream checkFile(filename.str());
        if (checkFile.is_open()) {
            std::cout << "File " << filename.str() << " already exists. Skipping.\n";
            continue;
        }

        std::ofstream keyFile(filename.str(), std::ios::out | std::ios::trunc);
        if (!keyFile.is_open()) {
            std::cerr << "Error opening file for writing key of " << attr << std::endl;
            continue;
        }

        keyFile << str_key;
        keyFile.close();
    }
    */

    // Run NDN Application
    ndn::examples::Producer producer(auth, decryptorID);
    producer.run();

    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
