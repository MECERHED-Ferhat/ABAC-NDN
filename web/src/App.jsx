import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import About from './pages/About'
import GettingStarted from './pages/GettingStarted'
import Architecture from './pages/Architecture'
import ApiAuthority from './pages/ApiAuthority'
import ApiEncryptor from './pages/ApiEncryptor'
import ApiDecryptor from './pages/ApiDecryptor'
import DataStructures from './pages/DataStructures'
import Benchmarks from './pages/Benchmarks'

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<About />} />
          <Route path="/getting-started" element={<GettingStarted />} />
          <Route path="/architecture" element={<Architecture />} />
          <Route path="/api/authority" element={<ApiAuthority />} />
          <Route path="/api/encryptor" element={<ApiEncryptor />} />
          <Route path="/api/decryptor" element={<ApiDecryptor />} />
          <Route path="/data-structures" element={<DataStructures />} />
          <Route path="/benchmarks" element={<Benchmarks />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
