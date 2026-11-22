import React from 'react';
import type { KeyPair, PayloadType, SignatureBundle } from '../types.ts';
import { arrayBufferToBase64, downloadTextFile, utf8ToBase64 } from '../utils/encoding.ts';
import { CodeBlock } from './CodeBlock.tsx';

interface TabSignProps {
  activeKeypair: KeyPair | null;
  activePassphrase: string;
  signTextInput: string;
  onSignTextInputChange: (val: string) => void;
  lastBundle: SignatureBundle | null;
  lastBundleJson: string | null;
  onSign: (params: {
    privatePem: string;
    dataB64: string;
    passphrase: string;
    payloadType: PayloadType;
    filename: string | null;
    rawTextIfTextMode?: string;
  }) => Promise<void>;
}

export const TabSign: React.FC<TabSignProps> = ({
  activeKeypair,
  activePassphrase,
  signTextInput,
  onSignTextInputChange,
  lastBundle,
  lastBundleJson,
  onSign,
}) => {
  const [keySource, setKeySource] = React.useState<'session' | 'upload'>('session');
  const [sessionPassphrase, setSessionPassphrase] = React.useState(activePassphrase);
  const [uploadedPrivPem, setUploadedPrivPem] = React.useState('');
  const [uploadedPrivName, setUploadedPrivName] = React.useState('');
  const [uploadPassphrase, setUploadPassphrase] = React.useState('');

  const [payloadMode, setPayloadMode] = React.useState<'text' | 'file'>('text');
  const [uploadedFileB64, setUploadedFileB64] = React.useState<string | null>(null);
  const [uploadedFileName, setUploadedFileName] = React.useState<string | null>(null);
  const [uploadedFileSize, setUploadedFileSize] = React.useState<number>(0);

  const [isSigning, setIsSigning] = React.useState(false);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [jsonExpanded, setJsonExpanded] = React.useState(false);

  React.useEffect(() => {
    setSessionPassphrase(activePassphrase);
  }, [activePassphrase]);

  const handlePrivUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setUploadedPrivPem('');
      setUploadedPrivName('');
      return;
    }
    const text = await file.text();
    setUploadedPrivPem(text);
    setUploadedPrivName(file.name);
  };

  const handlePayloadFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setUploadedFileB64(null);
      setUploadedFileName(null);
      setUploadedFileSize(0);
      return;
    }
    const buffer = await file.arrayBuffer();
    setUploadedFileB64(arrayBufferToBase64(buffer));
    setUploadedFileName(file.name);
    setUploadedFileSize(buffer.byteLength);
  };

  const handleSignSubmit = async () => {
    setSuccessMsg(null);
    setErrorMsg(null);

    const privatePemToUse = keySource === 'session' ? activeKeypair?.private_pem ?? '' : uploadedPrivPem;
    const passphraseToUse =
      keySource === 'session'
        ? activeKeypair?.encrypted
          ? sessionPassphrase
          : ''
        : uploadPassphrase;

    if (!privatePemToUse.trim()) {
      setErrorMsg('Please provide a valid Private Key before signing.');
      return;
    }

    let dataB64 = '';
    let payloadType: PayloadType = 'text';
    let filename: string | null = null;

    if (payloadMode === 'text') {
      if (!signTextInput) {
        setErrorMsg('Payload cannot be empty. Enter text or upload a non-empty file.');
        return;
      }
      dataB64 = utf8ToBase64(signTextInput);
      payloadType = 'text';
      filename = 'message.txt';
    } else {
      if (!uploadedFileB64 || uploadedFileSize === 0) {
        setErrorMsg('Payload cannot be empty. Enter text or upload a non-empty file.');
        return;
      }
      dataB64 = uploadedFileB64;
      payloadType = 'file';
      filename = uploadedFileName;
    }

    setIsSigning(true);
    try {
      await onSign({
        privatePem: privatePemToUse,
        dataB64,
        passphrase: passphraseToUse,
        payloadType,
        filename,
        rawTextIfTextMode: payloadMode === 'text' ? signTextInput : undefined,
      });
      setSuccessMsg('Payload signed! Signature bundle ready and synced to the Verify tab.');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Signing failed.');
    } finally {
      setIsSigning(false);
    }
  };

  const baseName = (lastBundle?.filename || 'payload').split('.').slice(0, -1).join('.') || lastBundle?.filename || 'payload';
  const sigFilename = `${baseName}.sig.json`;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-[#F8FAFC]">Create Detached Cryptographic Signature</h2>
        <p className="text-sm text-slate-300 mt-1">
          Sign UTF-8 text or raw binary files using your active session key or an uploaded PKCS#8{' '}
          <code className="px-1 py-0.5 rounded bg-slate-800 text-xs font-mono">.pem</code> private key.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-7 items-start">
        <div className="space-y-4">
          <div>
            <div className="text-sm font-medium text-slate-200 mb-2">Private Key Source</div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="sign-key-source"
                  checked={keySource === 'session'}
                  onChange={() => setKeySource('session')}
                  className="accent-[#3B82F6]"
                />
                Use Active Session Key
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="sign-key-source"
                  checked={keySource === 'upload'}
                  onChange={() => setKeySource('upload')}
                  className="accent-[#3B82F6]"
                />
                Upload Private Key (.pem)
              </label>
            </div>
          </div>

          {keySource === 'session' ? (
            activeKeypair === null ? (
              <div className="rounded-md bg-amber-950/50 border border-amber-700/70 p-3 text-sm text-amber-200">
                No active session key loaded. Generate one in Tab 1 or upload a <code>.pem</code> file.
              </div>
            ) : (
              <div className="space-y-2.5">
                <p className="text-xs text-slate-400">
                  Using session{' '}
                  <code className="px-1 py-0.5 rounded bg-slate-800 text-blue-300">{activeKeypair.algorithm}</code>{' '}
                  key (
                  <code className="px-1 py-0.5 rounded bg-slate-800 text-slate-300">
                    {activeKeypair.fingerprint_sha256.slice(0, 24)}...
                  </code>
                  )
                </p>
                {activeKeypair.encrypted && (
                  <div>
                    <label
                      htmlFor="sign-session-pass"
                      className="block text-sm font-medium text-slate-200 mb-1"
                    >
                      Enter Passphrase for Encrypted Session Key
                    </label>
                    <input
                      id="sign-session-pass"
                      type="password"
                      value={sessionPassphrase}
                      onChange={(e) => setSessionPassphrase(e.target.value)}
                      className="w-full rounded-md bg-[#111827] border border-slate-700 px-3 py-2 text-sm text-[#F8FAFC] focus:outline-none focus:border-[#3B82F6]"
                    />
                  </div>
                )}
              </div>
            )
          ) : (
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-slate-200 mb-1.5">
                  Upload private_key.pem
                </label>
                <input
                  type="file"
                  accept=".pem,.key,.txt"
                  onChange={handlePrivUpload}
                  className="block w-full text-sm text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-700 file:text-sm file:font-medium file:bg-[#111827] file:text-slate-200 hover:file:bg-slate-800 cursor-pointer"
                />
                {uploadedPrivName && (
                  <p className="text-xs text-slate-400 mt-1">Loaded {uploadedPrivName}</p>
                )}
              </div>
              <div>
                <label
                  htmlFor="sign-upload-pass"
                  className="block text-sm font-medium text-slate-200 mb-1"
                >
                  Private Key Passphrase (if encrypted)
                </label>
                <input
                  id="sign-upload-pass"
                  type="password"
                  value={uploadPassphrase}
                  onChange={(e) => setUploadPassphrase(e.target.value)}
                  className="w-full rounded-md bg-[#111827] border border-slate-700 px-3 py-2 text-sm text-[#F8FAFC] focus:outline-none focus:border-[#3B82F6]"
                />
              </div>
            </div>
          )}

          <hr className="border-slate-800" />

          <div>
            <div className="text-sm font-medium text-slate-200 mb-2">Payload Input Mode</div>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="sign-payload-mode"
                  checked={payloadMode === 'text'}
                  onChange={() => setPayloadMode('text')}
                  className="accent-[#3B82F6]"
                />
                Text Message (UTF-8)
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
                <input
                  type="radio"
                  name="sign-payload-mode"
                  checked={payloadMode === 'file'}
                  onChange={() => setPayloadMode('file')}
                  className="accent-[#3B82F6]"
                />
                Binary File Upload
              </label>
            </div>
          </div>

          {payloadMode === 'text' ? (
            <div>
              <label htmlFor="sign-text-area" className="block text-sm font-medium text-slate-200 mb-1.5">
                Message Payload to Sign
              </label>
              <textarea
                id="sign-text-area"
                rows={8}
                value={signTextInput}
                onChange={(e) => onSignTextInputChange(e.target.value)}
                className="w-full rounded-md bg-[#111827] border border-slate-700 p-3 text-sm text-[#F8FAFC] font-mono focus:outline-none focus:border-[#3B82F6]"
              />
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium text-slate-200 mb-1.5">
                Upload Any File to Sign (Raw Bytes)
              </label>
              <input
                type="file"
                onChange={handlePayloadFileUpload}
                className="block w-full text-sm text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-700 file:text-sm file:font-medium file:bg-[#111827] file:text-slate-200 hover:file:bg-slate-800 cursor-pointer"
              />
              {uploadedFileName && (
                <p className="text-xs text-slate-400 mt-1.5">
                  Loaded <code className="px-1 py-0.5 rounded bg-slate-800">{uploadedFileName}</code> (
                  {uploadedFileSize.toLocaleString()} bytes)
                </p>
              )}
            </div>
          )}

          <button
            type="button"
            onClick={handleSignSubmit}
            disabled={isSigning}
            className="w-full py-2.5 px-4 rounded-md bg-[#3B82F6] hover:bg-blue-500 disabled:opacity-60 text-white font-semibold text-sm transition-colors cursor-pointer"
          >
            {isSigning ? 'Signing Payload...' : '✍️ Generate Detached Signature'}
          </button>

          {successMsg && (
            <div className="rounded-md bg-emerald-950/60 border border-emerald-700/70 px-3.5 py-2.5 text-sm text-emerald-200">
              {successMsg}
            </div>
          )}
          {errorMsg && (
            <div className="rounded-md bg-red-950/60 border border-red-700/70 px-3.5 py-2.5 text-sm text-red-200">
              {errorMsg}
            </div>
          )}
        </div>

        <div className="space-y-4">
          {lastBundle === null ? (
            <div className="rounded-md bg-blue-950/50 border border-blue-800/70 p-4 text-sm text-blue-200">
              Sign a message or file on the left to inspect the detached Base64 signature and{' '}
              <code>.sig.json</code> bundle.
            </div>
          ) : (
            <>
              <h3 className="text-base font-semibold text-[#F8FAFC]">Detached Signature Output</h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">Algorithm</div>
                  <div className="text-lg font-semibold text-[#F8FAFC] mt-0.5">{lastBundle.algorithm}</div>
                </div>
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">Signed At (UTC)</div>
                  <div className="text-sm font-semibold text-[#F8FAFC] mt-1 font-mono">
                    {lastBundle.signed_at}
                  </div>
                </div>
              </div>

              <div>
                <div className="text-sm font-semibold text-slate-200 mb-1.5">Payload SHA-256 Digest:</div>
                <CodeBlock value={lastBundle.payload_sha256} />
              </div>

              <div>
                <div className="text-sm font-semibold text-slate-200 mb-1.5">
                  Signer Public Key Fingerprint (SHA-256):
                </div>
                <CodeBlock value={lastBundle.public_key_fingerprint} />
              </div>

              <div>
                <div className="text-sm font-semibold text-slate-200 mb-1.5">
                  Detached Signature (Base64):
                </div>
                <CodeBlock value={lastBundle.signature_b64} />
              </div>

              {lastBundleJson && (
                <div className="rounded-md border border-slate-800 bg-[#111827]/60 overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setJsonExpanded((prev) => !prev)}
                    className="w-full flex items-center justify-between px-4 py-2.5 text-sm font-medium text-slate-200 hover:bg-slate-800/60 transition-colors cursor-pointer"
                  >
                    <span>Preview Canonical .sig.json Bundle</span>
                    <span className="text-xs text-slate-400">{jsonExpanded ? '▼' : '▶'}</span>
                  </button>
                  {jsonExpanded && (
                    <div className="p-3 pt-0">
                      <CodeBlock value={lastBundleJson} />
                    </div>
                  )}
                </div>
              )}

              {lastBundleJson && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(lastBundleJson, sigFilename, 'application/json')}
                  className="w-full py-2 px-4 rounded-md bg-[#111827] hover:bg-slate-800 border border-slate-700 text-sm font-medium text-[#F8FAFC] transition-colors cursor-pointer"
                >
                  ⬇️ Download {sigFilename}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
