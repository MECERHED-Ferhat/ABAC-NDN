export default function Benchmarks() {
  return (
    <>
      <h1 className="page-title">Benchmarks</h1>
      <p className="page-subtitle">
        Performance evaluation of ABAC-NDN across hardware platforms and
        security configurations.
      </p>

      <div className="note-box">
        <strong>Coming soon.</strong> Benchmark results are being gathered
        from experiments on the NDN testbed. Results will be published here
        once available.
      </div>

      <h2>Planned Evaluation</h2>
      <p>
        The benchmark suite evaluates the library's performance across two
        dimensions: hardware capability and cryptographic security parameters.
      </p>

      <h3>Hardware Configurations</h3>
      <div className="dep-grid">
        <div className="dep-card">
          <div className="dep-card-name">Jetson Nano</div>
          <div className="dep-card-desc">
            ARM Cortex-A57 (1.43 GHz, 4 cores). Represents
            resource-constrained edge devices in IoT deployments.
          </div>
        </div>
        <div className="dep-card">
          <div className="dep-card-name">ESP32</div>
          <div className="dep-card-desc">
            Xtensa LX6 (240 MHz, dual-core). Ultra-constrained microcontroller
            target for lightweight IoT nodes.
          </div>
        </div>
        <div className="dep-card">
          <div className="dep-card-name">x86 Machine</div>
          <div className="dep-card-desc">
            Standard desktop / server CPU. Serves as the baseline reference
            platform for all cryptographic operations.
          </div>
        </div>
      </div>

      <h3>Security Configurations</h3>
      <p>
        Each hardware platform is evaluated under varying security
        configurations, including:
      </p>
      <ul>
        <li>Number of authorities (1 to N)</li>
        <li>Number of attributes per policy</li>
        <li>Policy complexity (tree depth and threshold values)</li>
        <li>Key material size</li>
      </ul>

      <h3>Testbed Topology</h3>
      <p>
        Experiments are conducted on a small NDN testbed consisting of three
        nodes connected via IP/UDP overlays with NFD:
      </p>
      <div className="card">
        <div className="card-title">Testbed setup</div>
        <p style={{ margin: 0, fontSize: '0.875rem' }}>
          <strong>authority1</strong> (x86 machine) — issues key material and
          manages revocation
          <br />
          <strong>producer1</strong> (Jetson Nano) — encrypts and streams
          sensor / IoT data
          <br />
          <strong>consumer1</strong> (ESP32 / x86) — decrypts and processes
          incoming data
        </p>
      </div>

      <h2>Metrics</h2>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Metric</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Setup time</td>
              <td>Time to generate global parameters</td>
            </tr>
            <tr>
              <td>Key generation time</td>
              <td>Time for an authority to generate one attribute key pair</td>
            </tr>
            <tr>
              <td>Encryption time</td>
              <td>Time to encrypt a fixed-size payload under a given policy</td>
            </tr>
            <tr>
              <td>Decryption time</td>
              <td>Time to recover the plaintext from a ciphertext</td>
            </tr>
            <tr>
              <td>Revocation + update time</td>
              <td>
                Time to revoke one attribute and deliver update tokens to
                remaining clients
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </>
  )
}
