import CodeBlock from '../components/CodeBlock'

export default function ApiEncryptor() {
  return (
    <>
      <h1 className="page-title">Encryptor API</h1>
      <p className="page-subtitle">
        The Encryptor role (data producer) retrieves public keys from the
        network, defines an access policy, and publishes encrypted data
        streams.
      </p>

      <div className="note-box">
        <strong>Role:</strong> An Encryptor is any NDN node that wishes to
        publish data that should only be accessible to consumers holding
        specific attribute combinations. It interacts with one or more
        authorities to fetch their public keys before encrypting.
      </div>

      <h2>publishEncryptedStream</h2>
      <p>
        The primary entry point for the Encryptor role. Encrypts a data
        stream under a given access policy and publishes it to the NDN
        network.
      </p>
      <CodeBlock
        language="cpp"
        label="MaAbeEncryptor.hpp"
        code={`int publishEncryptedStream(
    ndn::Face& face,
    const ndn::Name& prefix,
    const std::string& accessPolicy,
    std::function<std::istream&(void)> provider);`}
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
                An active NDN face connected to a local NFD instance. Used
                to express interests for public keys and to register the
                data prefix.
              </td>
            </tr>
            <tr>
              <td><code>prefix</code></td>
              <td><code>const ndn::Name&</code></td>
              <td>
                The NDN name under which the encrypted data stream will be
                published (e.g., <code>/DataStream/video/segment</code>).
              </td>
            </tr>
            <tr>
              <td><code>accessPolicy</code></td>
              <td><code>const std::string&</code></td>
              <td>
                The attribute-based access policy string. See the Access
                Policy Syntax section below.
              </td>
            </tr>
            <tr>
              <td><code>provider</code></td>
              <td>
                <code>std::function&lt;std::istream&amp;(void)&gt;</code>
              </td>
              <td>
                A callback that returns the data stream to be encrypted.
                Called once the library has collected the necessary public
                keys.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        Returns <code>0</code> on success or a negative error code on
        failure.
      </p>

      <h2>Access Policy Syntax</h2>
      <p>
        Access policies are expressed using a recursive threshold syntax:
      </p>
      <CodeBlock
        language="bash"
        label="policy syntax"
        code={`k/n(child1, child2, ..., childN)`}
      />
      <p>
        Where <code>k</code> is the minimum number of children that must be
        satisfied (threshold), <code>n</code> is the total number of
        children, and each child is either a leaf attribute name or a nested
        sub-policy.
      </p>

      <h3>Examples</h3>
      <CodeBlock
        language="bash"
        label="policy examples"
        code={`# Both ATTR_A and ATTR_B required (AND)
2/2(ATTR_A, ATTR_B)

# Either ATTR_A or ATTR_B (OR)
1/2(ATTR_A, ATTR_B)

# At least 2 of 3 attributes
2/3(ATTR_A, ATTR_B, ATTR_C)

# Nested: (ATTR_A AND ATTR_B) OR ATTR_C
1/2(2/2(ATTR_A, ATTR_B), ATTR_C)`}
      />

      <h2>Underlying C++ Class</h2>
      <CodeBlock
        language="cpp"
        label="MaAbeEncryptor — class overview"
        code={`class MaAbeEncryptor {
public:
    int publishEncryptedStream(
        ndn::Face& face,
        const ndn::Name& prefix,
        const std::string& accessPolicy,
        std::function<std::istream&(void)> provider);

    void fillPolicy(const AccessPolicy& ap);
    void updatePolicy(const AccessPolicy& ap);

private:
    std::map<std::string, PublicKey> publicKeys;
    // ...
};`}
      />

      <h2>Usage Example</h2>
      <CodeBlock
        language="cpp"
        label="example — encrypting a file"
        code={`#include <abac-ndn/MaAbeEncryptor.hpp>

int main() {
    ndn::Face face;
    MaAbeEncryptor enc;

    std::string policy = "2/2(DEPT_ENGINEERING, CLEARANCE_SECRET)";
    ndn::Name prefix("/org/data/report");

    enc.publishEncryptedStream(face, prefix, policy, []() -> std::istream& {
        static std::ifstream file("report.pdf", std::ios::binary);
        return file;
    });

    face.processEvents();
    return 0;
}`}
      />
    </>
  )
}
