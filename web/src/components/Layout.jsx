import { useState } from 'react'
import Sidebar from './Sidebar'
import ScrollToTop from './ScrollToTop'

export default function Layout({ children }) {
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <>
      <ScrollToTop />
      <div className="layout">
        <button
          className="hamburger"
          onClick={() => setMenuOpen(true)}
          aria-label="Open navigation menu"
        >
          <span />
          <span />
          <span />
        </button>

        {menuOpen && (
          <div
            className="sidebar-backdrop"
            onClick={() => setMenuOpen(false)}
          />
        )}

        <Sidebar isOpen={menuOpen} onClose={() => setMenuOpen(false)} />

        <main className="main-content">
          <div className="content-wrapper">{children}</div>
        </main>
      </div>
    </>
  )
}
