#include "ABAC-NDN/Consumer.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include "AccessPolicy.h"
#include "Authority.h"
#include "Encryptor.h"
#include "Decryptor.h"
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

// g++ -std=c++17 src/ndn_consumer.cpp ma_cp_abe/*.cpp -I. -I./utils $(pkg-config --cflags libndn-cxx) -L/usr/local/lib -lpbc -lgmp -lcryptopp $(pkg-config --libs libndn-cxx) -o ndn_consumer_app; export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH; ./ndn_consumer_app


// Suppression de la variable TURN


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Consumer
{
public:
  Consumer(const std::vector<std::string>& decryptor_attributes)
    : decryptor_attributes(decryptor_attributes)
  {
    
  }

  void run()
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
                             std::bind(&Consumer::onDataGlobalParameter, this,  _1, _2),
                             std::bind(&Consumer::onNack, this, _1, _2),
                             std::bind(&Consumer::onTimeout, this, _1));

      while (true) {
        m_face.processEvents();
      }
    //} 
  }

  void setPrefix(std::string tmp_prefix) {
    prefix = ndn::Name(tmp_prefix);
  }

private:
  int received_keys;
  int received_updates;
  MaCpAbeDecryptor* decryptor = nullptr;
  bool READ_KEYS = false;
  GlobalParameter tmp_GP;
  std::vector<std::string> decryptor_attributes;
  std::unordered_map<std::string, std::chrono::steady_clock::time_point> interestSendTimes;
  ndn::Name prefix;


  void
  onDataGlobalParameter(const Interest&, const Data& data)
  {
    std::cout << "Received Global Parameters" << std::endl;
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
    decryptor = new MaCpAbeDecryptor("decryptor", tmp_GP);

    received_keys = decryptor_attributes.size();
    received_updates = decryptor_attributes.size();
    
    if (READ_KEYS) {
      decryptor->loadClientKeys(decryptor_attributes);
      sendUpdate();
    } else {
      for (const auto& attr : decryptor_attributes) {
        Name nextName = prefix;
        nextName.append("ClientKey");
        nextName.append(attr);
        Interest nextInterest(nextName);
        nextInterest.setMustBeFresh(true);
        nextInterest.setInterestLifetime(6_s);

        std::cout << "Sending NEXT Interest " << nextInterest << std::endl;
        m_face.expressInterest(nextInterest,
                               std::bind(&Consumer::onDataClientkey, this, _1, _2),
                               std::bind(&Consumer::onNack, this, _1, _2),
                               std::bind(&Consumer::onTimeout, this, _1));
      }
    }
  }

  void
  onDataClientkey(const Interest&, const Data& data) {
    auto contentBlock = data.getContent();
    const uint8_t* contentPtr = contentBlock.value();
    size_t contentSize = contentBlock.value_size();
    std::string contentStr(reinterpret_cast<const char*>(contentPtr), contentSize);

    std::cout << "Received Data (as string): " << contentStr << std::endl;
    decryptor->loadClientKey(contentStr);

    received_keys--;
    if (received_keys <= 0) {
      sendUpdate();
    }
  }

  void
  onDataUpdate(const Interest&, const Data& data)
  {
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

    std::cout << "Received Data (as string): " << contentStr << std::endl;
    decryptor->loadClientUpdate(contentStr);

    received_updates--;
    if (received_updates <= 0) {
      Name kmName = prefix;
      kmName.append("KeyMaterial");
      Interest kmInterest(kmName);
      kmInterest.setMustBeFresh(true);
      kmInterest.setInterestLifetime(6_s);

      std::cout << "Sending KM Interest " << kmInterest << std::endl;

      auto now = std::chrono::steady_clock::now();
      interestSendTimes[kmInterest.getName().toUri()] = now;
      m_face.expressInterest(kmInterest,
                             std::bind(&Consumer::onDataKeymaterial, this, _1, _2),
                             std::bind(&Consumer::onNack, this, _1, _2),
                             std::bind(&Consumer::onTimeout, this, _1));
    }
  }

  void
  onDataKeymaterial(const ndn::Interest&, const ndn::Data& data)
  {
    std::cout << "D: Received KeyMaterial" << data << std::endl;
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

    std::istringstream iss(contentStr, std::ios::binary);
    auto AC = AccessPolicy::deserializeAC(iss);


    MaCpAbeClient::buildTree(AC->root, decryptor->root);
    if (decryptor->evaluatePolicy(AC->root)) {
      std::cout << "AC " << AC->policyString << " satisfied" << std::endl;
      element_t km_seed;
      element_init_GT(km_seed, decryptor->GP.e);
      decryptor->decrypt(*AC, decryptor->client_key_final, km_seed);
      decryptor->generateKeyMaterial(km_seed);

      Name dataName = prefix;
      dataName.append("Data");
      Interest dataInterest(dataName);
      dataInterest.setMustBeFresh(true);
      dataInterest.setInterestLifetime(6_s);

      std::cout << "Sending Data Interest " << dataInterest << std::endl;
      m_face.expressInterest(dataInterest,
                             std::bind(&Consumer::onDataStream, this, _1, _2),
                             std::bind(&Consumer::onNack, this, _1, _2),
                             std::bind(&Consumer::onTimeout, this, _1));

    }
  }

  void
  onDataStream(const ndn::Interest&, const ndn::Data& data)
  {
    auto contentBlock = data.getContent();
    const uint8_t* contentPtr = contentBlock.value();
    size_t contentSize = contentBlock.value_size();
    std::string encrypted_message(reinterpret_cast<const char*>(contentPtr), contentSize);

    decryptor->deriveSymmetricKey(1, CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::cout << decryptor->symmetric_key << std::endl;

    AESWrapper aes_dec(decryptor->symmetric_key, CryptoPP::AES::DEFAULT_KEYLENGTH);

    std::cout << "clear text: " << aes_dec.decryptAES(encrypted_message) << std::endl;
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


private:
  Face m_face;
  ValidatorConfig m_validator{m_face};

  void sendUpdate() {
    for (const auto& attr : decryptor_attributes) {
      Name nextName = prefix;
      nextName.append("Update");
      nextName.append(attr);
      Interest nextInterest(nextName);
      nextInterest.setMustBeFresh(true);
      nextInterest.setInterestLifetime(6_s);

      std::cout << "Sending NEXT Interest " << nextInterest << std::endl;
      auto now = std::chrono::steady_clock::now();
      interestSendTimes[nextInterest.getName().toUri()] = now;
      m_face.expressInterest(nextInterest,
                             std::bind(&Consumer::onDataUpdate, this, _1, _2),
                             std::bind(&Consumer::onNack, this, _1, _2),
                             std::bind(&Consumer::onTimeout, this, _1));
    }
  }
};

} // namespace examples
} // namespace ndn



int consumeEncryptedStream(const std::vector<std::string>& decryptor_attributes, const std::string tmp_prefix)
{
  try {
    ndn::examples::Consumer consumer(decryptor_attributes);
    consumer.setPrefix(tmp_prefix);
    consumer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
