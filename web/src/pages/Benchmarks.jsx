const PLATFORMS = [
  {
    name: 'ESP32-S3',
    type: 'Microcontroller',
    cpu: 'Xtensa LX7 dual-core, 240 MHz',
    ram: '512 KB',
    color: '#e67e22',
    note: 'Ultra-constrained IoT target',
  },
  {
    name: 'Jetson Nano',
    type: 'Edge Device',
    cpu: 'ARM Cortex-A57, quad-core',
    ram: '4 GB',
    color: '#1a6fad',
    note: 'Resource-constrained edge node',
  },
  {
    name: 'x86 Machine',
    type: 'Desktop / Server',
    cpu: 'AMD Ryzen 7 PRO 4750U',
    ram: '32 GB',
    note: 'Reference platform; also used for authority operations',
    color: '#27ae60',
  },
]

const PRIMITIVES = [
  { fn: 'GenerateMasterKey',   esp: null,   jetson: null,  x86: 0.12  },
  { fn: 'GeneratePublicKey',   esp: null,   jetson: null,  x86: 1.60  },
  { fn: 'UpdatePublicKey',     esp: null,   jetson: null,  x86: 1.08  },
  { fn: 'GenerateClientKey',   esp: null,   jetson: null,  x86: 2.74  },
  { fn: 'GenerateClientUpdate',esp: null,   jetson: null,  x86: 0.01  },
  { fn: 'Encrypt',             esp: 163.60, jetson: 30.00, x86: 3.01  },
  { fn: 'LoadClientUpdate',    esp: 38.00,  jetson: 4.259, x86: 0.87  },
  { fn: 'Decrypt',             esp: 822.30, jetson: 16.69, x86: 1.28  },
]

const ENCRYPT_SECURITY = [
  { device: 'ESP32',  typeA80: 163.6,  typeA112: 611.86,  typeA128: 1339.88, typeF80: 965.24,  typeF112: 1515.43, typeF128: 1737.43 },
  { device: 'Jetson', typeA80: 30.0,   typeA112: 112.2,   typeA128: 245.7,   typeF80: 177.0,   typeF112: 277.89,  typeF128: 318.6   },
  { device: 'x86',    typeA80: 3.01,   typeA112: 11.26,   typeA128: 24.65,   typeF80: 17.79,   typeF112: 27.88,   typeF128: 31.97   },
]

const DECRYPT_SECURITY = [
  { device: 'ESP32',  typeA80: 822.3,  typeA112: 4481.5,  typeA128: 12161.8, typeF80: 9242.7,  typeF112: 14326.1, typeF128: 16174.6 },
  { device: 'Jetson', typeA80: 16.7,   typeA112: 91.0,    typeA128: 246.9,   typeF80: 187.6,   typeF112: 290.8,   typeF128: 328.3   },
  { device: 'x86',    typeA80: 1.3,    typeA112: 7.0,     typeA128: 19.0,    typeF80: 14.4,    typeF112: 22.3,    typeF128: 25.2    },
]

const LATENCY = [
  { attrs: 2,  ms: 147.06 },
  { attrs: 4,  ms: 267.06 },
  { attrs: 6,  ms: 388.88 },
  { attrs: 8,  ms: 511.34 },
  { attrs: 10, ms: 632.74 },
]

const PACKET_SIZES = [
  { message: 'Global Parameter',        bytes: 132 },
  { message: 'Public Key',              bytes: 574 },
  { message: 'Update',                  bytes: 107 },
  { message: 'Key Material (per attr)', bytes: 567 },
]

function fmt(v) {
  if (v === null) return <span style={{ color: 'var(--color-text-muted)' }}>—</span>
  return v
}

function heatColor(v, max) {
  const ratio = Math.min(v / max, 1)
  if (ratio < 0.15) return 'rgba(39,174,96,0.12)'
  if (ratio < 0.4)  return 'rgba(241,196,15,0.12)'
  return 'rgba(231,76,60,0.12)'
}

export default function Benchmarks() {
  const latencyMax = Math.max(...LATENCY.map(r => r.ms))

  return (
    <>
      <h1 className="page-title">Benchmarks</h1>
      <p className="page-subtitle">
        Performance evaluation of ABAC-NDN on heterogeneous hardware platforms
        and a real NDN testbed. All times are in milliseconds (ms).
      </p>

      {/* ── Hardware platforms ── */}
      <h2>Test Platforms</h2>
      <p>
        Experiments were conducted on three platforms covering the full spectrum
        from ultra-constrained IoT microcontrollers to standard server hardware.
        Authority-side operations were measured on the x86 machine only, as they
        are not intended to run on embedded devices.
      </p>
      <div className="platform-grid">
        {PLATFORMS.map((p) => (
          <div
            key={p.name}
            className="platform-card"
            style={{ borderTopColor: p.color }}
          >
            <div className="platform-name" style={{ color: p.color }}>
              {p.name}
            </div>
            <div className="platform-type">{p.type}</div>
            <div className="platform-spec"><span>CPU</span>{p.cpu}</div>
            <div className="platform-spec"><span>RAM</span>{p.ram}</div>
            <div className="platform-note">{p.note}</div>
          </div>
        ))}
      </div>

      {/* ── Table 1: Primitive execution times ── */}
      <h2>Primitive Execution Times</h2>
      <p>
        Execution time of each cryptographic primitive on a single attribute.
        Authority operations (key generation) run only on the x86 machine.
        Client operations (encrypt, decrypt) are measured across all three
        platforms.
      </p>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Function</th>
              <th style={{ textAlign: 'right' }}>ESP32 (ms)</th>
              <th style={{ textAlign: 'right' }}>Jetson Nano (ms)</th>
              <th style={{ textAlign: 'right' }}>x86 (ms)</th>
            </tr>
          </thead>
          <tbody>
            {PRIMITIVES.map((row) => (
              <tr key={row.fn}>
                <td><code>{row.fn}</code></td>
                <td style={{ textAlign: 'right' }}>{fmt(row.esp)}</td>
                <td style={{ textAlign: 'right' }}>{fmt(row.jetson)}</td>
                <td style={{ textAlign: 'right' }}>{fmt(row.x86)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Tables 2 & 3: Security levels ── */}
      <h2>Security Level Analysis</h2>
      <p>
        Encryption and decryption times under two elliptic curve families —{' '}
        <strong>Type A</strong> and <strong>Type F</strong> — at three
        bit-security levels (80, 112, 128 bits). Higher security levels and
        Type F curves introduce significant overhead, especially on constrained
        devices. Cell shading indicates relative cost:{' '}
        <span style={{ background:'rgba(39,174,96,0.18)', padding:'1px 6px', borderRadius:3, fontSize:'0.8em' }}>fast</span>{' '}
        <span style={{ background:'rgba(241,196,15,0.18)', padding:'1px 6px', borderRadius:3, fontSize:'0.8em' }}>moderate</span>{' '}
        <span style={{ background:'rgba(231,76,60,0.18)', padding:'1px 6px', borderRadius:3, fontSize:'0.8em' }}>slow</span>.
      </p>

      <h3>Encryption</h3>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th rowSpan={2}>Device</th>
              <th colSpan={3} style={{ textAlign:'center', borderBottom:'1px solid var(--color-border)' }}>Type A</th>
              <th colSpan={3} style={{ textAlign:'center', borderBottom:'1px solid var(--color-border)' }}>Type F</th>
            </tr>
            <tr>
              <th style={{ textAlign:'right' }}>80-bit</th>
              <th style={{ textAlign:'right' }}>112-bit</th>
              <th style={{ textAlign:'right' }}>128-bit</th>
              <th style={{ textAlign:'right' }}>80-bit</th>
              <th style={{ textAlign:'right' }}>112-bit</th>
              <th style={{ textAlign:'right' }}>128-bit</th>
            </tr>
          </thead>
          <tbody>
            {ENCRYPT_SECURITY.map((row) => {
              const vals = [row.typeA80, row.typeA112, row.typeA128, row.typeF80, row.typeF112, row.typeF128]
              const max = Math.max(...ENCRYPT_SECURITY.flatMap(r => [r.typeA80,r.typeA112,r.typeA128,r.typeF80,r.typeF112,r.typeF128]))
              return (
                <tr key={row.device}>
                  <td><strong>{row.device}</strong></td>
                  {vals.map((v, i) => (
                    <td key={i} style={{ textAlign:'right', background: heatColor(v, max) }}>{v}</td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <h3>Decryption</h3>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th rowSpan={2}>Device</th>
              <th colSpan={3} style={{ textAlign:'center', borderBottom:'1px solid var(--color-border)' }}>Type A</th>
              <th colSpan={3} style={{ textAlign:'center', borderBottom:'1px solid var(--color-border)' }}>Type F</th>
            </tr>
            <tr>
              <th style={{ textAlign:'right' }}>80-bit</th>
              <th style={{ textAlign:'right' }}>112-bit</th>
              <th style={{ textAlign:'right' }}>128-bit</th>
              <th style={{ textAlign:'right' }}>80-bit</th>
              <th style={{ textAlign:'right' }}>112-bit</th>
              <th style={{ textAlign:'right' }}>128-bit</th>
            </tr>
          </thead>
          <tbody>
            {DECRYPT_SECURITY.map((row) => {
              const vals = [row.typeA80, row.typeA112, row.typeA128, row.typeF80, row.typeF112, row.typeF128]
              const max = Math.max(...DECRYPT_SECURITY.flatMap(r => [r.typeA80,r.typeA112,r.typeA128,r.typeF80,r.typeF112,r.typeF128]))
              return (
                <tr key={row.device}>
                  <td><strong>{row.device}</strong></td>
                  {vals.map((v, i) => (
                    <td key={i} style={{ textAlign:'right', background: heatColor(v, max) }}>{v}</td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* ── Network evaluation ── */}
      <h2>Network Evaluation</h2>
      <p>
        Network experiments used Raspberry Pi 3 B+ nodes in a star topology
        connected over Wi-Fi, powered by NFD. Cryptographic operations used the{' '}
        <code>SignatureSha256withECDSA</code> scheme.
      </p>

      <h3>Data Consumption Latency</h3>
      <p>
        Time from the initial Interest until the first data segment is decrypted
        and ready to use, measured against the number of attributes embedded in
        the key material ciphertext. Latency grows roughly linearly with the
        attribute count (~120 ms per additional 2 attributes).
      </p>

      <div className="latency-chart">
        {LATENCY.map((row) => (
          <div key={row.attrs} className="latency-row">
            <div className="latency-label">{row.attrs} attrs</div>
            <div className="latency-bar-wrap">
              <div
                className="latency-bar"
                style={{ width: `${(row.ms / latencyMax) * 100}%` }}
              />
              <span className="latency-value">{row.ms} ms</span>
            </div>
          </div>
        ))}
      </div>

      <h3>Packet Sizes</h3>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Message Type</th>
              <th style={{ textAlign: 'right' }}>Size (bytes)</th>
            </tr>
          </thead>
          <tbody>
            {PACKET_SIZES.map((row) => (
              <tr key={row.message}>
                <td>{row.message}</td>
                <td style={{ textAlign: 'right' }}>{row.bytes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="note-box" style={{ marginTop: 32 }}>
        <strong>Source:</strong> Mecerhed et al., "ABAC-NDN: An Open-Source
        Security Library for Attribute-Based Access Control in NDN", SAFER
        Workshop 2026.
      </div>
    </>
  )
}
