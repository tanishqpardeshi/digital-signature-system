import React from 'react';
import type { AlgorithmType, KeyPair } from '../types.ts';
import { downloadTextFile } from '../utils/encoding.ts';
import { CodeBlock } from './CodeBlock.tsx';

interface TabKeyManagementProps {
  activeKeypair: KeyPair | null;
  onGenerateKeypair: (algorithm: AlgorithmType, passphrase: string) => Promise<void>;
}

export const TabKeyManagement: React.FC<TabKeyManagementProps> = ({
  activeKeypair,
  onGenerateKeypair,
}) => {
  const [algorithmChoice, setAlgorithmChoice] = React.useState<AlgorithmType>('Ed25519');
  const [passphraseInput, setPassphraseInput] = React.useState('');
  const [isGenerating, setIsGenerating] = React.useState(false);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [previewExpanded, setPreviewExpanded] = React.useState(true);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      await onGenerateKeypair(algorithmChoice, passphraseInput);
      setSuccessMsg(`Generated ${algorithmChoice} key pair in memory.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to generate key pair.');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-[#F8FAFC]">Asymmetric Key Pair Generation</h2>
        <p className="text-sm text-slate-300 mt-1">
          Generate standards-compliant <strong>Ed25519</strong> (RFC 8032) or{' '}
          <strong>RSA-2048</strong> (PKCS#8 / SubjectPublicKeyInfo) keys strictly in volatile memory.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-7 items-start">
        <div className="lg:col-span-5 space-y-4">
          <div>
            <label htmlFor="alg-select" className="block text-sm font-medium text-slate-200 mb-1.5">
              Select Signature Algorithm
            </label>
            <select
              id="alg-select"
              value={algorithmChoice}
              onChange={(e) => setAlgorithmChoice(e.target.value as AlgorithmType)}
              title="Ed25519 is recommended for modern protocols: compact 32-byte keys and deterministic 64-byte signatures."
              className="w-full rounded-md bg-[#111827] border border-slate-700 px-3 py-2 text-sm text-[#F8FAFC] focus:outline-none focus:border-[#3B82F6]"
            >
              <option value="Ed25519">Ed25519</option>
              <option value="RSA-2048">RSA-2048</option>
            </select>
            <p className="text-xs text-slate-400 mt-1">
              Ed25519 is recommended for modern protocols: compact 32-byte keys and deterministic 64-byte signatures.
            </p>
          </div>

          <div>
            <label htmlFor="passphrase-input" className="block text-sm font-medium text-slate-200 mb-1.5">
              Optional Private Key Passphrase (PKCS#8 Encryption)
            </label>
            <input
              id="passphrase-input"
              type="password"
              value={passphraseInput}
              onChange={(e) => setPassphraseInput(e.target.value)}
              placeholder="Leave empty for unencrypted PEM..."
              className="w-full rounded-md bg-[#111827] border border-slate-700 px-3 py-2 text-sm text-[#F8FAFC] placeholder-slate-500 focus:outline-none focus:border-[#3B82F6]"
            />
            <p className="text-xs text-slate-400 mt-1">
              If provided, encrypts the PKCS#8 private key using BestAvailableEncryption (AES-256-CBC).
            </p>
          </div>

          <button
            type="button"
            onClick={handleGenerate}
            disabled={isGenerating}
            className="w-full py-2.5 px-4 rounded-md bg-[#3B82F6] hover:bg-blue-500 disabled:opacity-60 text-white font-semibold text-sm transition-colors cursor-pointer"
          >
            {isGenerating ? 'Generating Key Pair...' : 'Generate New Key Pair'}
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

        <div className="lg:col-span-7 space-y-4">
          {activeKeypair === null ? (
            <div className="rounded-md bg-blue-950/50 border border-blue-800/70 p-4 text-sm text-blue-200">
              Generate a key pair on the left (or run the 1-Click Quick-Start Demo) to inspect and export PEM credentials.
            </div>
          ) : (
            <>
              <div>
                <h3 className="text-base font-semibold text-[#F8FAFC] mb-2">
                  Active Public Key SHA-256 Fingerprint
                </h3>
                <CodeBlock value={activeKeypair.fingerprint_sha256} />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">Algorithm</div>
                  <div className="text-lg font-semibold text-[#F8FAFC] mt-0.5">{activeKeypair.algorithm}</div>
                </div>
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">PKCS#8 Encrypted</div>
                  <div className="text-lg font-semibold text-[#F8FAFC] mt-0.5">
                    {activeKeypair.encrypted ? 'Yes' : 'No'}
                  </div>
                </div>
                <div className="rounded-md bg-[#111827] border border-slate-800 p-3">
                  <div className="text-xs text-slate-400">Created UTC</div>
                  <div className="text-sm font-semibold text-[#F8FAFC] mt-1 font-mono">
                    {activeKeypair.created_at.replace('T', ' ').replace('Z', '')}
                  </div>
                </div>
              </div>

              <div className="rounded-md border border-slate-800 bg-[#111827]/60 overflow-hidden">
                <button
                  type="button"
                  onClick={() => setPreviewExpanded((prev) => !prev)}
                  className="w-full flex items-center justify-between px-4 py-2.5 text-sm font-medium text-slate-200 hover:bg-slate-800/60 transition-colors cursor-pointer"
                >
                  <span>Preview Public Key PEM (SubjectPublicKeyInfo)</span>
                  <span className="text-xs text-slate-400">{previewExpanded ? '▼' : '▶'}</span>
                </button>
                {previewExpanded && (
                  <div className="p-3 pt-0">
                    <CodeBlock value={activeKeypair.public_pem} />
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() =>
                    downloadTextFile(
                      activeKeypair.private_pem,
                      'private_key.pem',
                      'application/x-pem-file'
                    )
                  }
                  className="w-full py-2 px-4 rounded-md bg-[#111827] hover:bg-slate-800 border border-slate-700 text-sm font-medium text-[#F8FAFC] transition-colors cursor-pointer"
                >
                  ⬇️ Download private_key.pem
                </button>
                <button
                  type="button"
                  onClick={() =>
                    downloadTextFile(
                      activeKeypair.public_pem,
                      'public_key.pem',
                      'application/x-pem-file'
                    )
                  }
                  className="w-full py-2 px-4 rounded-md bg-[#111827] hover:bg-slate-800 border border-slate-700 text-sm font-medium text-[#F8FAFC] transition-colors cursor-pointer"
                >
                  ⬇️ Download public_key.pem
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
