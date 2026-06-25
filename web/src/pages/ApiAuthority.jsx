import CodeBlock from '../components/CodeBlock'

export default function ApiAuthority() {
  return (
    <>
      <h1 className="page-title">Authority API</h1>
      <p className="page-subtitle">
        The Authority role manages key material and access revocation for a
        set of attributes.
      </p>

      <div className="note-box">
        <strong>Role:</strong> An Authority node is responsible for a distinct
        set of attributes. It generates the master/public key pairs for each
        attribute and issues private keys to clients (consumers). Multiple
        authorities can coexist — each governs its own attributes
        independently.
      </div>

      <h2>Starting the Authority</h2>
      <p>
        Launch the authority process with its Global Identifier (GID) and the
        list of attributes it manages:
      </p>
      <CodeBlock
        language="bash"
        label="bash"
        code={`./MaAbeAuthorityNDN \\
    --gid AUTHORITY_GID \\
    --attrs ATTR_1,...,ATTR_N \\
    [--fetch-gp CONTENT_NAME]`}
      />

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Flag</th>
              <th>Required</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>--gid</code></td>
              <td><span className="badge badge-primary">Required</span></td>
              <td>
                The authority's Global Identifier. Used as the root of all
                NDN names published by this authority.
              </td>
            </tr>
            <tr>
              <td><code>--attrs</code></td>
              <td><span className="badge badge-primary">Required</span></td>
              <td>
                Comma-separated list of attributes this authority governs.
                The authority generates key material for each listed attribute.
              </td>
            </tr>
            <tr>
              <td><code>--fetch-gp</code></td>
              <td><span className="badge badge-accent">Optional</span></td>
              <td>
                NDN content name of an existing <code>GlobalParameter</code>{' '}
                to fetch from the network. If omitted, the authority generates
                new global parameters.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>Interactive Commands</h2>
      <p>
        Once running, the authority accepts interactive commands on its console:
      </p>
      <CodeBlock
        language="bash"
        label="authority shell"
        code={`authority> genkey CLIENT_GID ATTRIBUTE [OUTPUT_FILE]
authority> revoke CLIENT_GID ATTRIBUTE`}
      />

      <h3>genkey</h3>
      <p>
        Generates a private key for <code>CLIENT_GID</code> for the given{' '}
        <code>ATTRIBUTE</code>. The authority must own that attribute (i.e., it
        must have been listed in <code>--attrs</code>).
      </p>
      <ul>
        <li>
          <code>CLIENT_GID</code> — the Global Identifier of the client
          (consumer) receiving the key.
        </li>
        <li>
          <code>ATTRIBUTE</code> — the attribute for which the private key is
          generated.
        </li>
        <li>
          <code>OUTPUT_FILE</code> — optional path to write the key to disk.
          If omitted, the key is published directly to the NDN network under
          the client's name.
        </li>
      </ul>

      <h3>revoke</h3>
      <p>
        Revokes <code>CLIENT_GID</code>'s access to <code>ATTRIBUTE</code>.
        The authority:
      </p>
      <ol>
        <li>
          Announces a revocation notice at{' '}
          <code>/DOMAIN_PREFIX/RevokeNotify/GID_j</code>.
        </li>
        <li>
          Generates a new version <em>V_k+1</em> of the public key and
          publishes it.
        </li>
        <li>
          Issues update tokens to remaining valid clients so they can derive
          the new symmetric key without re-decrypting existing ciphertexts.
        </li>
      </ol>

      <h2>Underlying C++ Class</h2>
      <p>
        The authority functionality is implemented in{' '}
        <code>MaAbeAuthority</code>:
      </p>
      <CodeBlock
        language="cpp"
        label="MaAbeAuthority — key methods"
        code={`class MaAbeAuthority {
public:
    void generateMasterKey(const std::string& attr);
    void generatePublicKey(const std::string& attr);
    void updatePublicKey(const std::string& attr);

    void generateClientKey(const std::string& clientGid,
                           const std::string& attr);
    void generateClientUpdate(const std::string& clientGid,
                              const std::string& attr);
    // ...
private:
    std::string GID;
    std::vector<std::string> attributes;
    // master keys, public keys, client keys, update tokens...
};`}
      />
    </>
  )
}
