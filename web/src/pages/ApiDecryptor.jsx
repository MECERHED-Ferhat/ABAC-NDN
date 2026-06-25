import CodeBlock from '../components/CodeBlock'

export default function ApiDecryptor() {
  return (
    <>
      <h1 className="page-title">Decryptor API</h1>
      <p className="page-subtitle">
        The Decryptor role (data consumer) loads its private keys, evaluates
        access policies, and decrypts data streams from the NDN network.
      </p>

      <div className="note-box">
        <strong>Role:</strong> A Decryptor is any NDN node that wishes to
        consume encrypted data. It must have been issued private keys by one
        or more authorities — one key per attribute it holds. Decryption
        succeeds if and only if the consumer's attribute set satisfies the
        producer's access policy.
      </div>

      <h2>consumeEncryptedStream</h2>
      <p>
        The primary entry point for the Decryptor role. Fetches an encrypted
        data stream from the network, evaluates the embedded access policy,
        and writes the decrypted output.
      </p>
      <CodeBlock
        language="cpp"
        label="MaAbeDecryptor.hpp"
        code={`int consumeEncryptedStream(
    ndn::Face& face,
    const ndn::Name& prefix,
    std::ostream& output,
    std::function<void(const uint8_t* data, size_t size)>
        onSegment = nullptr);`}
      />

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Parameter</th>
              <th>Type</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>face</code></td>
              <td><code>ndn::Face&</code></td>
              <td>
                An active NDN face connected to a local NFD instance. Used to
                express interests for the data stream segments.
              </td>
            </tr>
            <tr>
              <td><code>prefix</code></td>
              <td><code>const ndn::Name&</code></td>
              <td>
                The NDN name of the encrypted data stream to fetch (must
                match the name used by the Encryptor).
              </td>
            </tr>
            <tr>
              <td><code>output</code></td>
              <td><code>std::ostream&</code></td>
              <td>
                The output stream to which the decrypted data is written
                (e.g., <code>std::cout</code> or a file stream).
              </td>
            </tr>
            <tr>
              <td><code>onSegment</code></td>
              <td>
                <code>std::function&lt;void(const uint8_t*, size_t)&gt;</code>
              </td>
              <td>
                Optional per-segment callback. Called with the raw decrypted
                bytes of each segment as it arrives, enabling streaming
                processing. Defaults to <code>nullptr</code>.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        Returns <code>0</code> on success, or a negative error code if the
        policy is not satisfied or decryption fails.
      </p>

      <h2>Loading Keys</h2>
      <p>
        Before calling <code>consumeEncryptedStream</code>, the decryptor
        must load the private keys it has received from authorities:
      </p>
      <CodeBlock
        language="cpp"
        label="MaAbeDecryptor — key loading"
        code={`class MaAbeDecryptor {
public:
    void loadClientKey(std::istream& input);
    void loadClientUpdate(std::istream& input);

    bool evaluatePolicy(const AccessPolicy& ap);

    int consumeEncryptedStream(
        ndn::Face& face,
        const ndn::Name& prefix,
        std::ostream& output,
        std::function<void(const uint8_t* data, size_t size)>
            onSegment = nullptr);

private:
    std::vector<std::string> attributes;
    PrivateKey clientKey;
    Update clientUpdate;
};`}
      />

      <h3>loadClientKey</h3>
      <p>
        Reads a private key from an input stream (e.g., a file previously
        written by the authority's <code>genkey</code> command). Can be
        called multiple times to load keys for different attributes.
      </p>

      <h3>loadClientUpdate</h3>
      <p>
        Loads a key update token issued by an authority after a revocation
        event. Required to derive the new version of the symmetric key when
        the access policy references an updated attribute.
      </p>

      <h3>evaluatePolicy</h3>
      <p>
        Checks whether the consumer's current set of private keys satisfies
        a given <code>AccessPolicy</code>. Returns <code>true</code> if
        decryption would succeed, <code>false</code> otherwise. Useful for
        pre-flight checks before attempting to fetch data.
      </p>

      <h2>Usage Example</h2>
      <CodeBlock
        language="cpp"
        label="example — decrypting a stream"
        code={`#include <abac-ndn/MaAbeDecryptor.hpp>
#include <fstream>

int main() {
    ndn::Face face;
    MaAbeDecryptor dec;

    // Load private keys issued by authorities
    std::ifstream keyA("key_DEPT_ENGINEERING.bin", std::ios::binary);
    std::ifstream keyB("key_CLEARANCE_SECRET.bin", std::ios::binary);
    dec.loadClientKey(keyA);
    dec.loadClientKey(keyB);

    ndn::Name prefix("/org/data/report");
    std::ofstream out("decrypted_report.pdf", std::ios::binary);

    int result = dec.consumeEncryptedStream(face, prefix, out);

    if (result == 0) {
        std::cout << "Decryption successful." << std::endl;
    } else {
        std::cerr << "Access denied or decryption failed." << std::endl;
    }

    face.processEvents();
    return result;
}`}
      />

      <div className="note-box warning">
        <strong>Policy not satisfied:</strong> If the consumer's attributes
        do not satisfy the access policy embedded in the ciphertext,{' '}
        <code>consumeEncryptedStream</code> returns a non-zero error code
        and writes nothing to the output stream.
      </div>
    </>
  )
}
