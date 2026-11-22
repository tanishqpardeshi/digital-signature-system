import React from 'react';

const COMPARISON_ROWS = [
  {
    dimension: 'Mathematical Foundation',
    ed25519: 'Edwards-curve Digital Signature Algorithm (Curve25519 / RFC 8032)',
    rsa2048: 'Integer Factorization over 2048-bit modulus (PKCS#1 v2.1 RSASSA-PSS)',
  },
  {
    dimension: 'Public Key Size',
    ed25519: '32 bytes (compact)',
    rsa2048: '256 bytes (~294 bytes DER SubjectPublicKeyInfo)',
  },
  {
    dimension: 'Detached Signature Size',
    ed25519: '64 bytes (88 Base64 chars)',
    rsa2048: '256 bytes (344 Base64 chars)',
  },
  {
    dimension: 'Determinism & Nonce Safety',
    ed25519: 'Fully deterministic (immune to weak CSPRNG nonce reuse)',
    rsa2048: 'Probabilistic (uses randomized MGF1 SHA-256 max-length salt)',
  },
  {
    dimension: 'Key Generation & Signing Speed',
    ed25519: 'Sub-millisecond keygen & ~50,000+ signatures/sec',
    rsa2048: '50–250 ms keygen (prime search); fast verification',
  },
  {
    dimension: 'Side-Channel Resistance',
    ed25519: 'Designed for constant-time execution without secret branches',
    rsa2048: 'Requires blinding and careful padding validation (PSS preferred over PKCS#1 v1.5)',
  },
];

export const TabArchitecture: React.FC = () => {
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-[#F8FAFC]">
        Digital Signature Architecture &amp; Security Guarantees
      </h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="rounded-md bg-[#111827] border border-slate-800 p-4 space-y-2">
          <h3 className="text-base font-semibold text-[#F8FAFC]">1. Authenticity</h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            Proves <strong>who</strong> signed the payload. Because only the signer possesses the private key,
            a valid verification with the corresponding public key cryptographically binds the origin.
          </p>
        </div>
        <div className="rounded-md bg-[#111827] border border-slate-800 p-4 space-y-2">
          <h3 className="text-base font-semibold text-[#F8FAFC]">2. Integrity</h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            Guarantees <strong>zero silent tampering</strong>. Even a single bit flip in a 100 MB binary
            file completely changes its SHA-256 digest (Avalanche Effect), causing signature verification to fail.
          </p>
        </div>
        <div className="rounded-md bg-[#111827] border border-slate-800 p-4 space-y-2">
          <h3 className="text-base font-semibold text-[#F8FAFC]">3. Non-Repudiation</h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            Prevents the signer from later denying having authorized the payload, provided the private key
            remained under their exclusive control and attested by a trusted PKI.
          </p>
        </div>
      </div>

      <hr className="border-slate-800" />

      <div className="space-y-3">
        <h3 className="text-base font-semibold text-[#F8FAFC]">
          Algorithm Comparison: Ed25519 vs. RSA-2048 (RSASSA-PSS + SHA-256)
        </h3>
        <div className="rounded-md border border-slate-800 overflow-x-auto bg-[#111827]">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-slate-900/90 text-slate-300">
                <th className="py-2.5 px-4 font-semibold border-b border-slate-800">Dimension</th>
                <th className="py-2.5 px-4 font-semibold border-b border-slate-800">
                  Ed25519 (Recommended Default)
                </th>
                <th className="py-2.5 px-4 font-semibold border-b border-slate-800">
                  RSA-2048 (PSS + SHA-256)
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-200">
              {COMPARISON_ROWS.map((row) => (
                <tr key={row.dimension} className="hover:bg-slate-900/40">
                  <td className="py-2.5 px-4 font-medium text-slate-100">{row.dimension}</td>
                  <td className="py-2.5 px-4 text-slate-300">{row.ed25519}</td>
                  <td className="py-2.5 px-4 text-slate-300">{row.rsa2048}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <hr className="border-slate-800" />

      <div className="space-y-3">
        <h3 className="text-base font-semibold text-[#F8FAFC]">
          Real-World Public Key Infrastructure (PKI) &amp; Certificate Authorities
        </h3>
        <div className="rounded-md bg-blue-950/50 border border-blue-800/70 p-4 text-sm text-blue-100 space-y-2.5 leading-relaxed">
          <p className="font-semibold">
            Why Public Key Fingerprints &amp; Certificate Authorities (CAs) Matter:
          </p>
          <p>
            A valid digital signature proves that <em>the holder of the matching private key</em> signed the
            data, but how do you know the public key truly belongs to Alice and wasn&apos;t substituted by an
            active Man-in-the-Middle attacker? In production systems:
          </p>
          <ol className="list-decimal list-inside space-y-1.5 pl-1">
            <li>
              <strong>Out-of-Band Fingerprint Verification:</strong> Users compare the colon-separated{' '}
              <strong>SHA-256 Public Key Fingerprint</strong> (computed over the DER{' '}
              <code className="px-1 py-0.5 rounded bg-blue-900/70 text-xs font-mono">
                SubjectPublicKeyInfo
              </code>
              ) against a trusted secondary channel.
            </li>
            <li>
              <strong>X.509 Certificates &amp; CAs:</strong> A trusted Certificate Authority (or enterprise
              HSM root CA) signs Alice&apos;s public key and identity attributes inside an X.509 certificate,
              establishing a verifiable chain of trust.
            </li>
            <li>
              <strong>Client-Side Hardware Signing:</strong> Production keys live inside hardware tokens
              (YubiKey, CloudHSM, Secure Enclave) so the raw private key bytes never leave the hardware
              boundary.
            </li>
          </ol>
        </div>
      </div>
    </div>
  );
};
