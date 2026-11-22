import React from 'react';
import { Sidebar } from './components/Sidebar.tsx';
import { TabArchitecture } from './components/TabArchitecture.tsx';
import { TabKeyManagement } from './components/TabKeyManagement.tsx';
import { TabSign } from './components/TabSign.tsx';
import { TabVerify } from './components/TabVerify.tsx';
import type {
  ActivityLogEntry,
  AlgorithmType,
  KeyPair,
  PayloadType,
  SignatureBundle,
  VerificationResult,
} from './types.ts';
import { SAMPLE_INVOICE_TEXT, utcTimestampCompact } from './utils/encoding.ts';

type TabId = 'keys' | 'sign' | 'verify' | 'architecture';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = React.useState<TabId>('keys');
  const [activeKeypair, setActiveKeypair] = React.useState<KeyPair | null>(null);
  const [activePassphrase, setActivePassphrase] = React.useState('');
  const [lastSignatureBundle, setLastSignatureBundle] = React.useState<SignatureBundle | null>(null);
  const [lastBundleJson, setLastBundleJson] = React.useState<string | null>(null);
  const [signTextInput, setSignTextInput] = React.useState(SAMPLE_INVOICE_TEXT);
  const [verifyTextInput, setVerifyTextInput] = React.useState(SAMPLE_INVOICE_TEXT);
  const [verifySignatureB64, setVerifySignatureB64] = React.useState('');
  const [verifyResult, setVerifyResult] = React.useState<VerificationResult | null>(null);
  const [activityLog, setActivityLog] = React.useState<ActivityLogEntry[]>([]);
  const [isQuickStartLoading, setIsQuickStartLoading] = React.useState(false);
  const [toastMessage, setToastMessage] = React.useState<string | null>(null);

  const appendLog = React.useCallback(
    (action: string, algorithm: string, fingerprint: string, status: string) => {
      const truncatedFingerprint =
        fingerprint.length > 24 ? `${fingerprint.slice(0, 24)}...` : fingerprint;
      const entry: ActivityLogEntry = {
        timeUtc: utcTimestampCompact(),
        action,
        algorithm,
        keyFingerprint: truncatedFingerprint,
        status,
      };
      setActivityLog((prev) => [entry, ...prev].slice(0, 20));
    },
    []
  );

  const showToast = React.useCallback((message: string) => {
    setToastMessage(message);
    setTimeout(() => {
      setToastMessage((curr) => (curr === message ? null : curr));
    }, 4000);
  }, []);

  const handleQuickStartDemo = async () => {
    setIsQuickStartLoading(true);
    try {
      const response = await fetch('/api/quick-start', { method: 'POST' });
      const data = (await response.json()) as {
        keypair?: KeyPair;
        bundle?: SignatureBundle;
        canonical_json?: string;
        verification?: VerificationResult;
        error?: string;
      };
      if (!response.ok || !data.keypair || !data.bundle || !data.verification) {
        throw new Error(data.error || 'Quick-Start Demo failed.');
      }

      setActiveKeypair(data.keypair);
      setActivePassphrase('');
      setLastSignatureBundle(data.bundle);
      setLastBundleJson(data.canonical_json ?? null);
      setSignTextInput(SAMPLE_INVOICE_TEXT);
      setVerifyTextInput(SAMPLE_INVOICE_TEXT);
      setVerifySignatureB64(data.bundle.signature_b64);
      setVerifyResult(data.verification);

      const newEntries: ActivityLogEntry[] = [
        {
          timeUtc: utcTimestampCompact(),
          action: 'Quick-Start Verify',
          algorithm: data.verification.algorithm,
          keyFingerprint:
            data.verification.public_key_fingerprint.length > 24
              ? `${data.verification.public_key_fingerprint.slice(0, 24)}...`
              : data.verification.public_key_fingerprint,
          status: data.verification.is_valid ? 'VALID' : 'INVALID',
        },
        {
          timeUtc: utcTimestampCompact(),
          action: 'Quick-Start Sign',
          algorithm: data.bundle.algorithm,
          keyFingerprint:
            data.bundle.public_key_fingerprint.length > 24
              ? `${data.bundle.public_key_fingerprint.slice(0, 24)}...`
              : data.bundle.public_key_fingerprint,
          status: 'SIGNED',
        },
        {
          timeUtc: utcTimestampCompact(),
          action: 'Quick-Start KeyGen',
          algorithm: data.keypair.algorithm,
          keyFingerprint:
            data.keypair.fingerprint_sha256.length > 24
              ? `${data.keypair.fingerprint_sha256.slice(0, 24)}...`
              : data.keypair.fingerprint_sha256,
          status: 'GENERATED',
        },
      ];
      setActivityLog((prev) => [...newEntries, ...prev].slice(0, 20));
      showToast('✅ Quick-Start Demo initialized! Open Tab 3 to test tampering.');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Quick-Start Demo failed.');
    } finally {
      setIsQuickStartLoading(false);
    }
  };

  const handleGenerateKeypair = async (algorithm: AlgorithmType, passphrase: string) => {
    const response = await fetch('/api/keypair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ algorithm, passphrase }),
    });
    const data = (await response.json()) as KeyPair & { error?: string };
    if (!response.ok) {
      throw new Error(data.error || 'Failed to generate key pair.');
    }
    setActiveKeypair(data);
    setActivePassphrase(passphrase);
    appendLog(
      'Generate KeyPair',
      data.algorithm,
      data.fingerprint_sha256,
      data.encrypted ? 'ENCRYPTED' : 'UNENCRYPTED'
    );
  };

  const handleSign = async (params: {
    privatePem: string;
    dataB64: string;
    passphrase: string;
    payloadType: PayloadType;
    filename: string | null;
    rawTextIfTextMode?: string;
  }) => {
    const response = await fetch('/api/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        private_pem: params.privatePem,
        data_b64: params.dataB64,
        passphrase: params.passphrase,
        payload_type: params.payloadType,
        filename: params.filename,
      }),
    });
    const data = (await response.json()) as {
      bundle?: SignatureBundle;
      canonical_json?: string;
      error?: string;
    };
    if (!response.ok || !data.bundle) {
      appendLog('Sign Error', 'Unknown', 'N/A', 'FAILED');
      throw new Error(data.error || 'Signing failed.');
    }

    setLastSignatureBundle(data.bundle);
    setLastBundleJson(data.canonical_json ?? null);
    if (params.payloadType === 'text' && params.rawTextIfTextMode !== undefined) {
      setVerifyTextInput(params.rawTextIfTextMode);
    }
    setVerifySignatureB64(data.bundle.signature_b64);
    appendLog(
      `Sign (${data.bundle.payload_type})`,
      data.bundle.algorithm,
      data.bundle.public_key_fingerprint,
      'SIGNED'
    );
  };

  const handleVerify = async (params: {
    publicPem: string;
    dataB64: string;
    signatureB64: string;
    actionLabel: string;
  }) => {
    const response = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_pem: params.publicPem,
        data_b64: params.dataB64,
        signature_b64: params.signatureB64,
      }),
    });
    const result = (await response.json()) as VerificationResult & { error?: string };
    if (!response.ok) {
      throw new Error(result.error || 'Verification failed.');
    }

    setVerifyResult(result);
    const statusLabel =
      params.actionLabel === 'Tamper Simulation'
        ? result.is_valid
          ? 'VALID'
          : 'TAMPERED / INVALID'
        : result.is_valid
          ? 'VALID'
          : 'INVALID';

    appendLog(params.actionLabel, result.algorithm, result.public_key_fingerprint, statusLabel);
  };

  const tabs: { id: TabId; label: string }[] = [
    { id: 'keys', label: '1. Key Management' },
    { id: 'sign', label: '2. Sign Message / File' },
    { id: 'verify', label: '3. Verify & Tamper Test' },
    { id: 'architecture', label: '4. How It Works & Architecture' },
  ];

  return (
    <div className="min-h-screen bg-[#0B0F19] text-[#F8FAFC] flex flex-col lg:flex-row">
      <Sidebar
        activeKeypair={activeKeypair}
        activityLog={activityLog}
        isQuickStartLoading={isQuickStartLoading}
        onQuickStartDemo={handleQuickStartDemo}
      />

      <main className="flex-1 min-w-0 px-5 py-6 md:px-10 md:py-8 max-w-6xl">
        <header className="space-y-2 mb-6">
          <h1 className="text-3xl font-bold tracking-tight text-[#F8FAFC]">
            🔐 Digital Signature Verification System
          </h1>
          <p className="text-sm text-slate-400">
            Modular Cryptographic Workbench — Ed25519 (RFC 8032) &amp; RSA-2048 (RSASSA-PSS + SHA-256)
            powered by Node.js <code className="px-1 py-0.5 rounded bg-slate-800 text-xs font-mono">crypto</code>.
          </p>

          <div className="mt-4 rounded-md bg-amber-950/45 border border-amber-700/70 px-4 py-3 text-sm text-amber-200">
            Educational Demo: All cryptographic operations run strictly in memory and no keys are stored on
            disk. In production systems, signing must happen locally on the client device—do not upload real
            production private keys here.
          </div>
        </header>

        <nav className="border-b border-slate-800 flex flex-wrap gap-6 mb-6" aria-label="Workbench Tabs">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`pb-2.5 text-sm font-medium border-b-2 transition-colors cursor-pointer ${
                  isActive
                    ? 'border-[#3B82F6] text-[#3B82F6]'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        <section>
          {activeTab === 'keys' && (
            <TabKeyManagement
              activeKeypair={activeKeypair}
              onGenerateKeypair={handleGenerateKeypair}
            />
          )}
          {activeTab === 'sign' && (
            <TabSign
              activeKeypair={activeKeypair}
              activePassphrase={activePassphrase}
              signTextInput={signTextInput}
              onSignTextInputChange={setSignTextInput}
              lastBundle={lastSignatureBundle}
              lastBundleJson={lastBundleJson}
              onSign={handleSign}
            />
          )}
          {activeTab === 'verify' && (
            <TabVerify
              activeKeypair={activeKeypair}
              verifyTextInput={verifyTextInput}
              onVerifyTextInputChange={setVerifyTextInput}
              verifySignatureB64={verifySignatureB64}
              onVerifySignatureB64Change={setVerifySignatureB64}
              verifyResult={verifyResult}
              onVerify={handleVerify}
            />
          )}
          {activeTab === 'architecture' && <TabArchitecture />}
        </section>
      </main>

      {toastMessage && (
        <div
          role="status"
          className="fixed bottom-5 right-5 z-50 rounded-md bg-[#111827] border border-slate-700 px-4 py-3 text-sm text-[#F8FAFC] shadow-xl"
        >
          {toastMessage}
        </div>
      )}
    </div>
  );
};

export default App;
