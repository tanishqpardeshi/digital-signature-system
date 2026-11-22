import React from 'react';
import type { KeyPair, SignatureBundle, VerificationResult } from '../types.ts';
import {
  arrayBufferToBase64,
  simulateTamperingOnText,
  utf8ToBase64,
} from '../utils/encoding.ts';
import { CodeBlock } from './CodeBlock.tsx';

interface TabVerifyProps {
  activeKeypair: KeyPair | null;
  verifyTextInput: string;
  onVerifyTextInputChange: (val: string) => void;
  verifySignatureB64: string;
  onVerifySignatureB64Change: (val: string) => void;
  verifyResult: VerificationResult | null;
  onVerify: (params: {
    publicPem: string;
    dataB64: string;
    signatureB64: string;
    actionLabel: string;
  }) => Promise<void>;
}

export const TabVerify: React.FC<TabVerifyProps> = ({
  activeKeypair,
  verifyTextInput,
  onVerifyTextInputChange,
  verifySignatureB64,
  onVerifySignatureB64Change,
  verifyResult,
  onVerify,
}) => {
  const [pubSource, setPubSource] = React.useState<'session' | 'upload'>('session');
  const [uploadedPubPem, setUploadedPubPem] = React.useState('');
  const [uploadedPubName, setUploadedPubName] = React.useState('');

  const [payloadMode, setPayloadMode] = React.useState<'text' | 'file'>('text');
  const [uploadedVerifyFileB64, setUploadedVerifyFileB64] = React.useState<string | null>(null);
  const [uploadedVerifyFileName, setUploadedVerifyFileName] = React.useState<string | null>(null);
  const [uploadedVerifyFileSize, setUploadedVerifyFileSize] = React.useState(0);

  const [sigInputMode, setSigInputMode] = React.useState<'paste' | 'bundle'>('paste');
  const [bundleSignatureB64, setBundleSignatureB64] = React.useState('');
  const [bundleExpectedSha256, setBundleExpectedSha256] = React.useState<string | null>(null);
  const [bundleMetaCaption, setBundleMetaCaption] = React.useState<string | null>(null);
  const [bundleError, setBundleError] = React.useState<string | null>(null);

  const [isVerifying, setIsVerifying] = React.useState(false);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);

  const publicPemToVerify = pubSource === 'session' ? activeKeypair?.public_pem ?? '' : uploadedPubPem;

  const handlePubUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setUploadedPubPem('');
      setUploadedPubName('');
      return;
    }
    const text = await file.text();
    setUploadedPubPem(text);
    setUploadedPubName(file.name);
  };

  const handleVerifyFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setUploadedVerifyFileB64(null);
      setUploadedVerifyFileName(null);
      setUploadedVerifyFileSize(0);
      return;
    }
    const buffer = await file.arrayBuffer();
    setUploadedVerifyFileB64(arrayBufferToBase64(buffer));
    setUploadedVerifyFileName(file.name);
    setUploadedVerifyFileSize(buffer.byteLength);
  };

  const handleBundleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setBundleError(null);
    setBundleMetaCaption(null);
    setBundleExpectedSha256(null);
    setBundleSignatureB64('');

    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const rawJson = await file.text();
      const response = await fetch('/api/bundle/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_json: rawJson }),
      });
      const data = (await response.json()) as { bundle?: SignatureBundle; error?: string };
      if (!response.ok || !data.bundle) {
        throw new Error(data.error || 'Failed to parse .sig.json bundle');
      }
      setBundleSignatureB64(data.bundle.signature_b64);
      setBundleExpectedSha256(data.bundle.payload_sha256);
      setBundleMetaCaption(`Loaded ${data.bundle.algorithm} bundle signed at ${data.bundle.signed_at}`);
    } catch (err) {
      setBundleError(err instanceof Error ? err.message : 'Invalid .sig.json bundle');
    }
  };

  const signatureB64ToVerify = sigInputMode === 'paste' ? verifySignatureB64 : bundleSignatureB64;

  const handleSimulateTampering = async () => {
    setErrorMsg(null);
    const mutated = simulateTamperingOnText(verifyTextInput);
    onVerifyTextInputChange(mutated);

    if (publicPemToVerify.trim() && signatureB64ToVerify.trim()) {
      setIsVerifying(true);
      try {
        await onVerify({
          publicPem: publicPemToVerify,
          dataB64: utf8ToBase64(mutated),
          signatureB64: signatureB64ToVerify,
          actionLabel: 'Tamper Simulation',
        });
      } finally {
        setIsVerifying(false);
      }
    }
  };

  const handleVerifyClick = async () => {
    setErrorMsg(null);
    let dataB64: string | null = null;
    if (payloadMode === 'text') {
      dataB64 = utf8ToBase64(verifyTextInput);
    } else {
      dataB64 = uploadedVerifyFileB64;
    }

    if (dataB64 === null) {
      setErrorMsg('Please provide payload text or upload a file to verify.');
      return;
    }

    setIsVerifying(true);
    try {
      await onVerify({
        publicPem: publicPemToVerify,
        dataB64,
        signatureB64: signatureB64ToVerify,
        actionLabel: 'Verify Signature',
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Verification request failed.');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-[#F8FAFC]">Verify Signature &amp; Interactive Tamper Laboratory</h2>
        <p className="text-sm text-slate-300 mt-1">
          Verify payload authenticity and integrity against a public key. Use <strong>Simulate Tampering</strong>{' '}
          to mutate a single byte and watch cryptographic verification immediately reject the forged payload.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-7 items-start">
        <div className="lg:col-span-6 space-y-4">
          <div>
            <div className="text-sm font-medium text-slate-200 mb-2">Public Key Source</div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="verify-pub-source"
                  checked={pubSource === 'session'}
                  onChange={() => setPubSource('session')}
                  className="accent-[#3B82F6]"
                />
                Use Active Session Public Key
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="verify-pub-source"
                  checked={pubSource === 'upload'}
                  onChange={() => setPubSource('upload')}
                  className="accent-[#3B82F6]"
                />
                Upload Public Key (public_key.pem)
              </label>
            </div>
          </div>

          {pubSource === 'session' ? (
            activeKeypair === null ? (
              <div className="rounded-md bg-amber-950/50 border border-amber-700/70 p-3 text-sm text-amber-200">
                No active session key. Generate one, click Quick-Start Demo, or upload <code>public_key.pem</code>.
              </div>
            ) : (
              <p className="text-xs text-slate-400">
                Using session{' '}
                <code className="px-1 py-0.5 rounded bg-slate-800 text-blue-300">{activeKeypair.algorithm}</code>{' '}
                public key (
                <code className="px-1 py-0.5 rounded bg-slate-800 text-slate-300">
                  {activeKeypair.fingerprint_sha256.slice(0, 24)}...
                </code>
                )
              </p>
            )
          ) : (
            <div>
              <label className="block text-sm font-medium text-slate-200 mb-1.5">
                Upload public_key.pem
              </label>
              <input
                type="file"
                accept=".pem,.pub,.txt"
                onChange={handlePubUpload}
                className="block w-full text-sm text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-700 file:text-sm file:font-medium file:bg-[#111827] file:text-slate-200 hover:file:bg-slate-800 cursor-pointer"
              />
              {uploadedPubName && (
                <p className="text-xs text-slate-400 mt-1">Loaded {uploadedPubName}</p>
              )}
            </div>
          )}

          <hr className="border-slate-800" />

          <div>
            <div className="text-sm font-medium text-slate-200 mb-2">Payload to Verify</div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="verify-payload-mode"
                  checked={payloadMode === 'text'}
                  onChange={() => setPayloadMode('text')}
                  className="accent-[#3B82F6]"
                />
                Text Message (UTF-8)
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="verify-payload-mode"
                  checked={payloadMode === 'file'}
                  onChange={() => setPayloadMode('file')}
                  className="accent-[#3B82F6]"
                />
                Binary File Upload
              </label>
            </div>
          </div>

          {payloadMode === 'text' ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-semibold text-slate-200">Message Content (UTF-8)</span>
                <button
                  type="button"
                  onClick={handleSimulateTampering}
                  disabled={isVerifying}
                  title="Mutates one character in the message and automatically re-runs verification."
                  className="py-1.5 px-3 rounded-md bg-[#111827] hover:bg-slate-800 border border-slate-600 text-xs font-medium text-[#F8FAFC] transition-colors cursor-pointer"
                >
                  🧪 Simulate Tampering
                </button>
              </div>
              <textarea
                rows={7}
                value={verifyTextInput}
                onChange={(e) => onVerifyTextInputChange(e.target.value)}
                aria-label="Verify Message Payload"
                className="w-full rounded-md bg-[#111827] border border-slate-700 p-3 text-sm text-[#F8FAFC] font-mono focus:outline-none focus:border-[#3B82F6]"
              />
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium text-slate-200 mb-1.5">
                Upload File to Verify
              </label>
              <input
                type="file"
                onChange={handleVerifyFileUpload}
                className="block w-full text-sm text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-700 file:text-sm file:font-medium file:bg-[#111827] file:text-slate-200 hover:file:bg-slate-800 cursor-pointer"
              />
              {uploadedVerifyFileName && (
                <p className="text-xs text-slate-400 mt-1.5">
                  Loaded <code className="px-1 py-0.5 rounded bg-slate-800">{uploadedVerifyFileName}</code> (
                  {uploadedVerifyFileSize.toLocaleString()} bytes)
                </p>
              )}
            </div>
          )}

          <hr className="border-slate-800" />

          <div>
            <div className="text-sm font-medium text-slate-200 mb-2">Signature Source</div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="verify-sig-source"
                  checked={sigInputMode === 'paste'}
                  onChange={() => setSigInputMode('paste')}
                  className="accent-[#3B82F6]"
                />
                Paste Base64 Detached Signature
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="verify-sig-source"
                  checked={sigInputMode === 'bundle'}
                  onChange={() => setSigInputMode('bundle')}
                  className="accent-[#3B82F6]"
                />
                Upload Signature Bundle (.sig.json)
              </label>
            </div>
          </div>

          {sigInputMode === 'paste' ? (
            <div>
              <label htmlFor="verify-sig-b64" className="block text-sm font-medium text-slate-200 mb-1.5">
                Base64 Signature String
              </label>
              <textarea
                id="verify-sig-b64"
                rows={4}
                value={verifySignatureB64}
                onChange={(e) => onVerifySignatureB64Change(e.target.value)}
                placeholder="Paste detached Base64 signature here..."
                className="w-full rounded-md bg-[#111827] border border-slate-700 p-3 text-sm text-[#F8FAFC] font-mono placeholder-slate-500 focus:outline-none focus:border-[#3B82F6]"
              />
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium text-slate-200 mb-1.5">
                Upload .sig.json Bundle
              </label>
              <input
                type="file"
                accept=".json"
                onChange={handleBundleUpload}
                className="block w-full text-sm text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-700 file:text-sm file:font-medium file:bg-[#111827] file:text-slate-200 hover:file:bg-slate-800 cursor-pointer"
              />
              {bundleMetaCaption && <p className="text-xs text-slate-400 mt-1.5">{bundleMetaCaption}</p>}
              {bundleError && (
                <div className="mt-2 rounded-md bg-red-950/60 border border-red-700/70 px-3 py-2 text-sm text-red-200">
                  Invalid .sig.json bundle: {bundleError}
                </div>
              )}
            </div>
          )}

          <button
            type="button"
            onClick={handleVerifyClick}
            disabled={isVerifying}
            className="w-full py-2.5 px-4 rounded-md bg-[#3B82F6] hover:bg-blue-500 disabled:opacity-60 text-white font-semibold text-sm transition-colors cursor-pointer"
          >
            {isVerifying ? 'Verifying Signature...' : '🛡️ Verify Cryptographic Signature'}
          </button>

          {errorMsg && (
            <div className="rounded-md bg-red-950/60 border border-red-700/70 px-3.5 py-2.5 text-sm text-red-200">
              {errorMsg}
            </div>
          )}
        </div>

        <div className="lg:col-span-6 space-y-4">
          <h3 className="text-base font-semibold text-[#F8FAFC]">Cryptographic Verification Verdict</h3>
          {verifyResult === null ? (
            <div className="rounded-md bg-blue-950/50 border border-blue-800/70 p-4 text-sm text-blue-200">
              Click <strong>Verify Cryptographic Signature</strong> (or{' '}
              <strong>1-Click Quick-Start Demo</strong>) to inspect verification telemetry.
            </div>
          ) : (
            <>
              {verifyResult.is_valid ? (
                <div className="rounded-[10px] bg-[#064E3B] border-2 border-[#10B981] p-5">
                  <h4 className="text-lg font-bold text-[#ECFDF5] mb-1.5">✅ SIGNATURE VALID</h4>
                  <p className="text-sm text-[#A7F3D0] m-0">
                    Authenticity &amp; Integrity Confirmed — The payload matches the cryptographic signature
                    produced by the holder of the private key.
                  </p>
                </div>
              ) : (
                <div className="rounded-[10px] bg-[#7F1D1D] border-2 border-[#EF4444] p-5">
                  <h4 className="text-lg font-bold text-[#FEF2F2] mb-1.5">
                    🚨 SIGNATURE INVALID / TAMPERED
                  </h4>
                  <p className="text-sm text-[#FECACA] m-0">
                    Cryptographic Verification Failed — Do NOT trust this payload. Either the content was
                    altered, the signature is malformed, or the wrong public key was supplied.
                  </p>
                </div>
              )}

              <p className="text-sm text-slate-200">
                <strong>Diagnostic Reason:</strong> {verifyResult.reason}
              </p>

              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">Detected Key Algorithm</div>
                  <div className="text-lg font-semibold text-[#F8FAFC] mt-0.5">{verifyResult.algorithm}</div>
                </div>
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">Verification Status</div>
                  <div
                    className={`text-lg font-semibold mt-0.5 ${
                      verifyResult.is_valid ? 'text-emerald-400' : 'text-red-400'
                    }`}
                  >
                    {verifyResult.is_valid ? 'AUTHENTIC' : 'REJECTED'}
                  </div>
                </div>
              </div>

              <div>
                <div className="text-sm font-semibold text-slate-200 mb-1.5">
                  Computed Payload SHA-256 Digest:
                </div>
                <CodeBlock value={verifyResult.payload_sha256} />
              </div>

              {bundleExpectedSha256 && sigInputMode === 'bundle' && (
                <div>
                  <div className="text-sm font-semibold text-slate-200 mb-1.5">
                    Expected SHA-256 Digest (from .sig.json):
                  </div>
                  <CodeBlock value={bundleExpectedSha256} />
                </div>
              )}

              <div>
                <div className="text-sm font-semibold text-slate-200 mb-1.5">
                  Public Key SHA-256 Fingerprint:
                </div>
                <CodeBlock value={verifyResult.public_key_fingerprint} />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
