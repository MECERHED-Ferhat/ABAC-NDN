export default function Architecture() {
  return (
    <>
      <h1 className="page-title">Architecture</h1>
      <p className="page-subtitle">
        How ABAC-NDN is structured and where it sits in the NDN software
        stack.
      </p>

      <h2>Stack Position</h2>
      <p>
        ABAC-NDN acts as a security middleware layer between an NDN
        application and the NDN/NFD networking layer. Applications interact
        with the library through one of three role interfaces — Authority,
        Encryptor, or Decryptor — without needing knowledge of the
        underlying cryptographic scheme.
      </p>

      <div className="arch-diagram">
        {/* NDN Application */}
        <div className="arch-layer">
          <div className="arch-layer-label">NDN Application</div>
          <div className="arch-boxes-row">
            <div className="arch-box">Security Administration</div>
            <div className="arch-box">Data Producer</div>
            <div className="arch-box">Data Consumer</div>
          </div>
        </div>

        {/* Roles connector */}
        <div className="arch-roles">
          <div className="arch-role authority">Authority</div>
          <div className="arch-role encryptor">Encryptor</div>
          <div className="arch-role decryptor">Decryptor</div>
        </div>

        {/* Security Library */}
        <div className="arch-layer">
          <div className="arch-layer-label">Security Library — ABAC-NDN</div>
          <div className="arch-columns">
            <div className="arch-column">
              <div className="arch-column-title crypto">Cryptographic Functions</div>
              <div className="arch-box">System Setup</div>
              <div className="arch-box">Key Generation</div>
              <div className="arch-box">Encrypt ABE</div>
              <div className="arch-box">Decrypt ABE</div>
              <div className="arch-box">Symmetric Operations</div>
            </div>
            <div className="arch-column">
              <div className="arch-column-title comm">Communication</div>
              <div className="arch-box">Communication Manager</div>
              <div className="arch-box-row">
                <div className="arch-box sub">NDN Naming</div>
                <div className="arch-box sub">Serialization</div>
              </div>
              <div className="arch-box-row">
                <div className="arch-box sub">Send</div>
                <div className="arch-box sub">Receive</div>
              </div>
              <div className="arch-box" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                NDN-CXX
              </div>
            </div>
            <div className="arch-column">
              <div className="arch-column-title data">Data Structures</div>
              <div className="arch-box">Global Parameter</div>
              <div className="arch-box">Access Policy</div>
              <div className="arch-box">Public Key</div>
              <div className="arch-box">Private Key</div>
              <div className="arch-box">Update</div>
            </div>
          </div>
        </div>

        <div className="arch-arrow">↓</div>

        {/* NDN/NFD */}
        <div className="arch-layer">
          <div className="arch-nfd">NDN / NFD</div>
        </div>
      </div>

      <h2>Internal Modules</h2>

      <h3>Cryptographic Functions</h3>
      <p>
        The cryptographic core implements the Decentralized
        Attribute-Based Encryption (MA-ABE) scheme. It exposes five
        operations:
      </p>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Operation</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>System Setup</code></td>
              <td>
                Generates global public parameters (pairing group,
                generator) shared across all authorities.
              </td>
            </tr>
            <tr>
              <td><code>Key Generation</code></td>
              <td>
                Authorities derive per-attribute master keys, public keys,
                and client private keys.
              </td>
            </tr>
            <tr>
              <td><code>Encrypt ABE</code></td>
              <td>
                Encrypts a symmetric key under a given attribute-based
                access policy using collected public keys.
              </td>
            </tr>
            <tr>
              <td><code>Decrypt ABE</code></td>
              <td>
                Decrypts the symmetric key if the client's private key
                satisfies the embedded access policy.
              </td>
            </tr>
            <tr>
              <td><code>Symmetric Operations</code></td>
              <td>
                AES encryption / decryption of the actual data payload
                using the recovered symmetric key.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h3>Data Structures</h3>
      <p>
        Data structures are serializable objects that can be published to
        and retrieved from the NDN network. They include{' '}
        <code>GlobalParameter</code>, <code>AccessPolicy</code>,{' '}
        <code>PublicKey</code>, <code>PrivateKey</code>, and{' '}
        <code>Update</code>. See the{' '}
        <a href="/data-structures">Data Structures</a> page for full
        details.
      </p>

      <h3>Communication</h3>
      <p>
        The communication module handles the NDN-specific aspects of the
        library:
      </p>
      <ul>
        <li>
          <strong>NDN Naming</strong> — translates library concepts (GID,
          attribute, version) into NDN content names following the
          library's naming convention.
        </li>
        <li>
          <strong>Library Serialization</strong> — encodes and decodes
          data structures for transport as NDN data packets.
        </li>
        <li>
          <strong>Send / Receive (NDN-CXX)</strong> — wraps{' '}
          <code>ndn::Face</code> to express interests and register prefixes
          for data publication.
        </li>
      </ul>

      <h2>NDN Naming Convention</h2>
      <p>
        The library uses a structured naming scheme rooted at a configurable{' '}
        <code>/DOMAIN_PREFIX</code>. Key material and revocation notices
        follow this hierarchy:
      </p>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Control Function</th>
              <th>NDN Name</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Global Parameters</td>
              <td><code>/DOMAIN_PREFIX/GlobalParameter/GID_j</code></td>
            </tr>
            <tr>
              <td>Public Key</td>
              <td><code>/DOMAIN_PREFIX/PublicKey/GID_j/ATTR_x[/V_k]</code></td>
            </tr>
            <tr>
              <td>Update Key</td>
              <td><code>/DOMAIN_PREFIX/Update/GID_j/ATTR_x[/V_k]</code></td>
            </tr>
            <tr>
              <td>Revocation Notice</td>
              <td><code>/DOMAIN_PREFIX/RevokeNotify/GID_j</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p style={{ fontSize: '0.83rem', color: 'var(--color-text-muted)' }}>
        <strong>GID_j</strong>: Global Identifier of Entity j &nbsp;·&nbsp;{' '}
        <strong>ATTR_x</strong>: Attribute x &nbsp;·&nbsp;{' '}
        <strong>V_k</strong>: Version k (used for key updates after revocation)
      </p>

      <h2>AC Roles</h2>
      <p>
        A node can operate in one of three roles. Roles map directly to
        application functions:
      </p>
      <div className="role-grid">
        <div className="role-card authority">
          <div className="role-card-header">
            <div className="role-card-dot" />
            <h4>Authority</h4>
          </div>
          <ul>
            <li>Generates master, public, and client private keys</li>
            <li>Publishes public keys to the NDN network</li>
            <li>Manages attribute revocation and key updates</li>
          </ul>
        </div>
        <div className="role-card encryptor">
          <div className="role-card-header">
            <div className="role-card-dot" />
            <h4>Encryptor</h4>
          </div>
          <ul>
            <li>Fetches public keys from the network</li>
            <li>Defines attribute-based access policies</li>
            <li>Encrypts and publishes data streams</li>
          </ul>
        </div>
        <div className="role-card decryptor">
          <div className="role-card-header">
            <div className="role-card-dot" />
            <h4>Decryptor</h4>
          </div>
          <ul>
            <li>Loads private keys issued by authorities</li>
            <li>Evaluates access policy satisfaction</li>
            <li>Decrypts ABE ciphertexts and data streams</li>
          </ul>
        </div>
      </div>
    </>
  )
}
