import CodeBlock from '../components/CodeBlock'

export default function GettingStarted() {
  return (
    <>
      <h1 className="page-title">Getting Started</h1>
      <p className="page-subtitle">
        How to install ABAC-NDN and verify your setup.
      </p>

      <h2>Prerequisites</h2>
      <p>
        Before installing ABAC-NDN, ensure the following dependencies are
        available on your system:
      </p>
      <div className="dep-grid">
        <div className="dep-card">
          <div className="dep-card-name">GMP / PBC</div>
          <div className="dep-card-desc">
            GNU Multiple Precision Arithmetic and the Pairing-Based
            Cryptography library — the cryptographic foundation.
          </div>
        </div>
        <div className="dep-card">
          <div className="dep-card-name">Crypto++</div>
          <div className="dep-card-desc">
            Used for symmetric-key operations (AES encryption / decryption
            of data streams).
          </div>
        </div>
        <div className="dep-card">
          <div className="dep-card-name">ndn-cxx</div>
          <div className="dep-card-desc">
            The C++ library for NDN application development. Provides
            <code>Face</code>, <code>Name</code>, and Interest/Data
            primitives.
          </div>
        </div>
        <div className="dep-card">
          <div className="dep-card-name">NFD</div>
          <div className="dep-card-desc">
            Named Data Networking Forwarding Daemon. Must be running on the
            host for the library's communication layer to function.
          </div>
        </div>
      </div>

      <h2>Installation</h2>

      <h3>1. Clone the repository</h3>
      <CodeBlock
        language="bash"
        label="bash"
        code={`git clone https://github.com/your-org/ABAC-NDN.git
cd ABAC-NDN`}
      />

      <h3>2. Configure with CMake</h3>
      <CodeBlock
        language="bash"
        label="bash"
        code={`cmake .`}
      />

      <h3>3. Compile</h3>
      <CodeBlock
        language="bash"
        label="bash"
        code={`make`}
      />

      <h3>4. Install system-wide</h3>
      <CodeBlock
        language="bash"
        label="bash"
        code={`sudo make install
sudo ldconfig`}
      />

      <div className="note-box">
        <strong>Note:</strong> <code>ldconfig</code> updates the dynamic
        linker cache so that applications can find the newly installed shared
        library without specifying its path explicitly.
      </div>

      <h2>Verify the Installation</h2>
      <p>
        Check that the library headers and shared object were installed
        correctly:
      </p>
      <CodeBlock
        language="bash"
        label="bash"
        code={`ls /usr/local/lib | grep ABAC
ls /usr/local/include | grep ABAC`}
      />
      <p>
        Both commands should return at least one matching entry. If neither
        does, re-run <code>sudo make install</code> and check for errors in
        the build output.
      </p>

      <h2>Quick Start</h2>
      <p>
        The library exposes three roles: <strong>Authority</strong>,{' '}
        <strong>Encryptor</strong>, and <strong>Decryptor</strong>. A minimal
        working setup requires:
      </p>
      <ol>
        <li>
          Starting an <strong>Authority</strong> node to generate and
          publish key material.
        </li>
        <li>
          Running an <strong>Encryptor</strong> (producer) that retrieves
          public keys and publishes encrypted data with an access policy.
        </li>
        <li>
          Running a <strong>Decryptor</strong> (consumer) that fetches its
          private key from the authority and decrypts the data stream.
        </li>
      </ol>
      <p>
        See the <strong>API Reference</strong> section for detailed usage of
        each role.
      </p>

      <div className="note-box tip">
        <strong>Tip:</strong> NFD must be running before starting any of the
        three role processes. Start it with <code>nfd-start</code>.
      </div>
    </>
  )
}
