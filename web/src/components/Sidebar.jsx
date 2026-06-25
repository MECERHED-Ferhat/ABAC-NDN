import { NavLink } from 'react-router-dom'

const NAV = [
  {
    group: 'Introduction',
    items: [
      { to: '/', label: 'About', end: true },
      { to: '/getting-started', label: 'Getting Started' },
    ],
  },
  {
    group: 'Library',
    items: [
      { to: '/architecture', label: 'Architecture' },
      { to: '/data-structures', label: 'Data Structures' },
    ],
  },
  {
    group: 'API Reference',
    items: [
      { to: '/api/authority', label: 'Authority' },
      { to: '/api/encryptor', label: 'Encryptor' },
      { to: '/api/decryptor', label: 'Decryptor' },
    ],
  },
  {
    group: 'Resources',
    items: [
      { to: '/benchmarks', label: 'Benchmarks' },
    ],
  },
]

const EXTERNAL = [
  {
    href: 'https://github.com/MECERHED-Ferhat/ABAC-NDN',
    label: 'GitHub Repository',
  },
  {
    href: 'https://ndncomm2026.named-data.net/assets/talks/organized_talks/04_Security_Library_Ferhat_Mecerhed/slides.pdf',
    label: 'Slides (PDF)',
  },
  {
    href: 'https://www.sciencedirect.com/science/article/pii/S157087052500335X',
    label: 'Paper (paywall)',
  },
]

export default function Sidebar({ isOpen, onClose }) {
  return (
    <aside className={`sidebar${isOpen ? ' open' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">A</div>
          ABAC-NDN
        </div>
        <div className="sidebar-tagline">
          Decentralized Access Control<br />for Named Data Networking
        </div>
        <button
          className="sidebar-close-btn"
          onClick={onClose}
          aria-label="Close navigation menu"
        >
          ✕
        </button>
      </div>

      <nav className="sidebar-nav">
        {NAV.map((section) => (
          <div className="nav-group" key={section.group}>
            <div className="nav-group-label">{section.group}</div>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onClose}
                className={({ isActive }) =>
                  'nav-link' + (isActive ? ' active' : '')
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
        ))}

        <div className="nav-group">
          <div className="nav-group-label">External</div>
          {EXTERNAL.map((link) => (
            <a
              key={link.href}
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              className="nav-link nav-link-external"
              onClick={onClose}
            >
              {link.label}
              <span className="nav-external-icon">↗</span>
            </a>
          ))}
        </div>
      </nav>

      <div className="sidebar-footer">
        v0.1.0 &nbsp;·&nbsp; C++ / NDN
      </div>
    </aside>
  )
}
