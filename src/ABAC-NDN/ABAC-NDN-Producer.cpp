#include "ABAC-NDN/Producer.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include "Authority.h"
#include "Encryptor.h"
#include "Global.h"
#include "AESWrapper.h"
#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <cryptopp/aes.h>
#include <chrono>
#include <unordered_map>



// g++ -std=c++17 src/ndn_producer.cpp ma_cp_abe/*.cpp -I. -I./utils $(pkg-config --cflags libndn-cxx) -L/usr/local/lib -lpbc -lgmp -lcryptopp $(pkg-config --libs libndn-cxx) -o ndn_producer_app; export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH; ./ndn_producer_app

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Producer
{
public:
  Producer(const std::vector<std::string>& encryptor_attributes)
  : encryptor_attributes(encryptor_attributes)
  {

  }

  void
  run()
  {
    m_validator.load("trust-schema.conf");
    //while (1) {
      Name interestName = prefix;
      interestName.append("GlobalParameter");
      //interestName.appendVersion();

      Interest interest(interestName);
      interest.setMustBeFresh(false);
      interest.setInterestLifetime(6_s); // The default is 4 seconds

      std::cout << "Sending Interest " << interest << std::endl;
      auto now = std::chrono::steady_clock::now();
      interestSendTimes[interest.getName().toUri()] = now;
      m_face.expressInterest(interest,
                             std::bind(&Producer::onDataGlobalParameter, this,  _1, _2),
                             std::bind(&Producer::onNack, this, _1, _2),
                             std::bind(&Producer::onTimeout, this, _1));
    //}
      while (true) {
        m_face.processEvents();
      }
  }

  void setPrefix(std::string tmp_prefix) {
    prefix = ndn::Name(tmp_prefix);
  }

  void setAccDesc(std::string tmp_acc_desc) {
    acc_desc = tmp_acc_desc;
  }

  void setData(std::string tmp_data) {
    data_to_send = tmp_data;
  }

private:
int received_pk;
public_key_map_t public_keys;
MaCpAbeEncryptor* encryptor = nullptr;
AccessPolicy *AC;
GlobalParameter tmp_GP;
std::vector<std::string> encryptor_attributes;
std::unordered_map<std::string, std::chrono::steady_clock::time_point> interestSendTimes;
ndn::Name prefix;
std::string acc_desc = "";
std::string data_to_send = "";


  void
  onDataGlobalParameter(const Interest&, const Data& data)
  {
    std::cout << "Received Data " << data << std::endl;
    auto receiveTime = std::chrono::steady_clock::now();
    auto it = interestSendTimes.find(data.getName().toUri());
    if (it != interestSendTimes.end()) {
      auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(receiveTime - it->second).count();
      std::cout << "RTT for " << data.getName() << " = " << rtt << " ms" << std::endl;
      interestSendTimes.erase(it);
    }


    auto contentBlock = data.getContent();
    auto contentPtr = contentBlock.value(); // const uint8_t*
    size_t contentSize = contentBlock.value_size(); // size of content

    std::vector<uint8_t> generator_bytes(contentPtr, contentPtr + contentSize);

    MaCpAbeClient::deserializeGlobalParameter(tmp_GP, generator_bytes);
    encryptor = new MaCpAbeEncryptor("encryptor", tmp_GP);
    AC = new AccessPolicy();
    AC->setPolicy(acc_desc);

    received_pk = encryptor_attributes.size();
    for (const std::string attr : encryptor_attributes) {
      Name nextName = prefix;
      nextName.append("PublicKey");
      nextName.append(attr);
      Interest nextInterest(nextName);
      nextInterest.setMustBeFresh(true);
      nextInterest.setInterestLifetime(6_s);

      std::cout << "Sending NEXT Interest " << nextInterest << std::endl;
      auto now = std::chrono::steady_clock::now();
      interestSendTimes[nextInterest.getName().toUri()] = now;

      m_face.expressInterest(nextInterest,
                             std::bind(&Producer::onDataPublickey, this, _1, _2),
                             std::bind(&Producer::onNack, this, _1, _2),
                             std::bind(&Producer::onTimeout, this, _1));
    }
  }

  void
  onDataPublickey(const Interest&, const Data& data)
  {
    std::cout << "Received Data " << data << std::endl;
    auto receiveTime = std::chrono::steady_clock::now();
    auto it = interestSendTimes.find(data.getName().toUri());
    if (it != interestSendTimes.end()) {
      auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(receiveTime - it->second).count();
      std::cout << "RTT for " << data.getName() << " = " << rtt << " ms" << std::endl;
      interestSendTimes.erase(it);
    }

    auto contentBlock = data.getContent();
    const uint8_t* contentPtr = contentBlock.value();
    size_t contentSize = contentBlock.value_size();
    std::string contentStr(reinterpret_cast<const char*>(contentPtr), contentSize);

    MaCpAbeEncryptor::deserializePublicKey(contentStr, public_keys);

    received_pk--;
    if (received_pk <= 0) {
      element_t km_seed;
      element_init_GT(km_seed, encryptor->GP.e);
      element_random(km_seed);

      encryptor->encrypt(km_seed, *AC, public_keys, {});
      encryptor->generateKeyMaterial(km_seed);

      Name lstKM = prefix;
      Name lstData = prefix;
      lstKM.append("KeyMaterial");
      lstData.append("Data");
      m_face.setInterestFilter(lstKM,
                               std::bind(&Producer::onInterestKeymaterial, this, _2),
                               nullptr, // RegisterPrefixSuccessCallback is optional
                               std::bind(&Producer::onRegisterFailed, this, _1, _2));
      m_face.setInterestFilter(lstData,
                               std::bind(&Producer::onInterestData, this, _2),
                               nullptr, // RegisterPrefixSuccessCallback is optional
                               std::bind(&Producer::onRegisterFailed, this, _1, _2));

      auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
      m_certServeHandle = m_face.setInterestFilter(security::extractIdentityFromCertName(cert.getName()),
                                                   [this, cert] (auto&&...) {
                                                     m_face.put(cert);
                                                   },
                                                   std::bind(&Producer::onRegisterFailed, this, _1, _2));      
    }
  }

  void
  onInterestKeymaterial(const ndn::Interest& interest)
  {
    std::cout << ">> I: " << interest << std::endl;

    auto data = std::make_shared<ndn::Data>();
    data->setName(interest.getName());
    data->setFreshnessPeriod(10_s);

    std::ostringstream oss(std::ios::binary);
    AccessPolicy::serializeAC(oss, *AC);
    
    data->setContent(oss.str());

    m_keyChain.sign(*data);
    m_face.put(*data);
  }

  void
  onInterestData(const ndn::Interest& interest)
  {
    std::cout << ">> I: " << interest << std::endl;

    auto data = std::make_shared<ndn::Data>();
    data->setName(interest.getName());
    data->setFreshnessPeriod(10_s);



    // Symmetric part
    encryptor->deriveSymmetricKey(1, CryptoPP::AES::DEFAULT_KEYLENGTH);
    AESWrapper aes_enc(encryptor->symmetric_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::string encrypted_message = aes_enc.encryptAES(data_to_send);
    
    data->setContent(encrypted_message);

    m_keyChain.sign(*data);
    m_face.put(*data);
  }

  void
  onNack(const Interest&, const lp::Nack& nack) const
  {
    std::cout << "Received Nack with reason " << nack.getReason() << std::endl;
  }

  void
  onTimeout(const Interest& interest) const
  {
    std::cout << "Timeout for " << interest << std::endl;
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
  ValidatorConfig m_validator{m_face};

  /*
  void
  startAsymEncryption() {
    element_t km_seed;
    element_init_GT(km_seed, encryptor->GP.e);
    element_random(km_seed);

    encryptor->encrypt(km_seed, *AC, public_keys, {});
    encryptor->generateKeyMaterial(km_seed);
  }
  */
};

} // namespace examples
} // namespace ndn



int publishEncryptedStream(const std::vector<std::string>& encryptor_attributes, const std::string tmp_prefix, const std::string tmp_acc_desc, const std::string tmp_data)
{
  try {

    ndn::examples::Producer producer(encryptor_attributes);
    producer.setPrefix(tmp_prefix);
    producer.setAccDesc(tmp_acc_desc);
    producer.setData(tmp_data);
    producer.run();

    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
