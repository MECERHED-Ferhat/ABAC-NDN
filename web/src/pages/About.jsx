export default function About() {
  return (
    <>
      <h1 className="page-title">ABAC-NDN</h1>
      <p className="page-subtitle">
        An open-source C++ library for decentralized Attribute-Based Access
        Control in Named Data Networking.
      </p>

      <h2>Overview</h2>
      <p>
        ABAC-NDN is a free C++ security library that implements a{' '}
        <strong>Multi-Authority Attribute-Based Encryption (MA-ABE)</strong>{' '}
        scheme for Named Data Networking (NDN). Built on top of{' '}
        <code>ndn-cxx</code> and the PBC pairing library, it allows data
        producers and consumers to enforce fine-grained, policy-based
        encryption without relying on a central authority.
      </p>
      <p>
        The library sits between an NDN application and the NDN/NFD
        networking layer, providing transparent encryption and decryption of
        data streams according to configurable attribute-based access
        policies.
      </p>

      <h2>The NDN Confidentiality Problem</h2>
      <p>
        Communication in NDN follows a <strong>group-based model</strong>{' '}
        induced by two core mechanisms:
      </p>
      <ul>
        <li>
          <strong>Pending Interest Table (PIT)</strong> — multiple consumers
          can express interest in the same named content simultaneously.
        </li>
        <li>
          <strong>In-network caching</strong> — routers cache and replay
          data packets to satisfy future interests, meaning a data packet
          may reach unintended recipients from cache.
        </li>
      </ul>
      <p>
        These properties make traditional peer-to-peer encrypted tunnels
        (e.g., TLS sessions) ill-suited for NDN. Instead, confidentiality
        must be achieved through <strong>encryption schemes</strong> that
        protect content itself, independently of who fetches it and how.
      </p>

      <h2>Solution: Multi-Authority ABE</h2>
      <p>
        ABAC-NDN implements a Multi-Authority Attribute-Based Encryption
        scheme with three key properties that address NDN's requirements:
      </p>
      <div className="feature-grid">
        <div className="feature-card">
          <h4>Attribute-Based Access</h4>
          <p>
            Access granularity is determined by attributes, not identities.
            Any user holding the right combination of attributes can decrypt
            content.
          </p>
        </div>
        <div className="feature-card">
          <h4>No Central Authority</h4>
          <p>
            Each authority manages its own distinct set of attributes
            independently. No single entity controls the entire system.
          </p>
        </div>
        <div className="feature-card">
          <h4>One-to-Many Communication</h4>
          <p>
            Encrypted data can be accessed by multiple users simultaneously,
            as long as they satisfy the embedded access policy — perfectly
            aligned with NDN's group-based model.
          </p>
        </div>
        <div className="feature-card">
          <h4>NDN-Native</h4>
          <p>
            Built on <code>ndn-cxx</code> and NFD. Follows NDN naming
            conventions for key publication and revocation over the network.
          </p>
        </div>
      </div>

      <h2>Publication</h2>
      <div className="card">
        <div className="card-title">NDN Community Meeting 2026</div>
        <p>
          <em>
            "A Security Library of a Decentralized Access Control in NDN"
          </em>
          <br />
          Ferhat Mecerhed, Youcef Imine, Antoine Gallais, Stefan Fischer,
          Mohamed Ahmed Hail
          <br />
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>
            Universität zu Lübeck &amp; Université Polytechnique
            Hauts-de-France
          </span>
        </p>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '4px' }}>
          <a
            href="https://ndncomm2026.named-data.net/assets/talks/organized_talks/04_Security_Library_Ferhat_Mecerhed/slides.pdf"
            target="_blank"
            rel="noopener noreferrer"
            className="badge badge-primary"
            style={{ textDecoration: 'none' }}
          >
            Slides (PDF) ↗
          </a>
          <a
            href="https://www.sciencedirect.com/science/article/pii/S157087052500335X"
            target="_blank"
            rel="noopener noreferrer"
            className="badge badge-accent"
            style={{ textDecoration: 'none' }}
            title="Access may require institutional login"
          >
            Paper ↗ (paywall)
          </a>
        </div>
      </div>

      <h2>Source Code</h2>
      <p>
        ABAC-NDN is open-source software. The source code is hosted on GitHub.
      </p>
      <a
        href="https://github.com/MECERHED-Ferhat/ABAC-NDN"
        target="_blank"
        rel="noopener noreferrer"
        className="badge badge-primary"
        style={{ textDecoration: 'none', fontSize: '0.8rem', padding: '5px 14px' }}
      >
        github.com/MECERHED-Ferhat/ABAC-NDN ↗
      </a>
    </>
  )
}
