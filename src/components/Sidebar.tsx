import React from 'react';
import type { ActivityLogEntry, KeyPair } from '../types.ts';
import { CodeBlock } from './CodeBlock.tsx';

interface SidebarProps {
  activeKeypair: KeyPair | null;
  activityLog: ActivityLogEntry[];
  isQuickStartLoading: boolean;
  onQuickStartDemo: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeKeypair,
  activityLog,
  isQuickStartLoading,
  onQuickStartDemo,
}) => {
  const encBadge = activeKeypair?.encrypted ? 'Encrypted (PKCS#8)' : 'Unencrypted (In-Memory)';

  return (
    <aside className="w-full lg:w-[340px] xl:w-[360px] shrink-0 bg-[#111827] border-b lg:border-b-0 lg:border-r border-slate-800 p-5 flex flex-col gap-5">
      <div>
        <h2 className="text-xl font-bold text-[#F8FAFC]">Cryptographic Control Panel</h2>
        <p className="text-xs text-slate-400 mt-1">
          Instant evaluator workflow &amp; ephemeral session telemetry.
        </p>

        <button
          type="button"
          onClick={onQuickStartDemo}
          disabled={isQuickStartLoading}
          title="Generates an ephemeral Ed25519 key pair, signs a sample invoice, and pre-populates the Verify tab."
          className="mt-4 w-full py-2.5 px-4 rounded-md bg-[#3B82F6] hover:bg-blue-500 disabled:opacity-60 text-white font-semibold text-sm transition-colors cursor-pointer flex items-center justify-center gap-2 shadow-sm"
        >
          <span>⚡</span>
          <span>{isQuickStartLoading ? 'Initializing Demo...' : '1-Click Quick-Start Demo'}</span>
        </button>
      </div>

      <hr className="border-slate-800" />

      <div>
        <h3 className="text-base font-semibold text-[#F8FAFC] mb-2">Active Session Key Card</h3>
        {activeKeypair === null ? (
          <div className="rounded-md bg-blue-950/50 border border-blue-800/70 p-3.5 text-sm text-blue-200">
            No active key pair in session. Generate one in Tab 1 or click the Quick-Start Demo button above.
          </div>
        ) : (
          <div className="space-y-2 text-sm text-slate-200">
            <div>
              <span className="font-semibold text-slate-300">Algorithm: </span>
              <code className="px-1.5 py-0.5 rounded bg-slate-800 text-blue-300 text-xs font-mono">
                {activeKeypair.algorithm}
              </code>
            </div>
            <div>
              <span className="font-semibold text-slate-300">Protection: </span>
              <code className="px-1.5 py-0.5 rounded bg-slate-800 text-emerald-300 text-xs font-mono">
                {encBadge}
              </code>
            </div>
            <div>
              <span className="font-semibold text-slate-300">Created (UTC): </span>
              <code className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-xs font-mono">
                {activeKeypair.created_at}
              </code>
            </div>
            <div className="pt-1">
              <div className="font-semibold text-slate-300 mb-1.5">SHA-256 Fingerprint:</div>
              <CodeBlock value={activeKeypair.fingerprint_sha256} />
            </div>
          </div>
        )}
      </div>

      <hr className="border-slate-800" />

      <div className="flex-1 min-h-0 flex flex-col">
        <h3 className="text-base font-semibold text-[#F8FAFC]">In-Memory Session Activity Log</h3>
        <p className="text-xs text-slate-400 mt-1 mb-3">
          Showing last 20 operations (zero private keys or raw payloads logged).
        </p>

        {activityLog.length > 0 ? (
          <div className="rounded-md border border-slate-800 overflow-x-auto max-h-72 overflow-y-auto bg-[#0B0F19]">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="bg-slate-900/90 text-slate-400 sticky top-0">
                <tr>
                  <th className="py-2 px-2.5 font-medium border-b border-slate-800">Time UTC</th>
                  <th className="py-2 px-2.5 font-medium border-b border-slate-800">Action</th>
                  <th className="py-2 px-2.5 font-medium border-b border-slate-800">Algorithm</th>
                  <th className="py-2 px-2.5 font-medium border-b border-slate-800">Key Fingerprint</th>
                  <th className="py-2 px-2.5 font-medium border-b border-slate-800">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-200">
                {activityLog.map((entry, idx) => (
                  <tr key={`${entry.timeUtc}-${entry.action}-${idx}`} className="hover:bg-slate-900/50">
                    <td className="py-1.5 px-2.5 whitespace-nowrap font-mono text-[11px] text-slate-400">
                      {entry.timeUtc}
                    </td>
                    <td className="py-1.5 px-2.5 whitespace-nowrap">{entry.action}</td>
                    <td className="py-1.5 px-2.5 whitespace-nowrap">{entry.algorithm}</td>
                    <td className="py-1.5 px-2.5 whitespace-nowrap font-mono text-[11px] text-slate-300">
                      {entry.keyFingerprint}
                    </td>
                    <td className="py-1.5 px-2.5 whitespace-nowrap font-semibold">
                      <span
                        className={
                          entry.status.includes('INVALID') ||
                          entry.status.includes('TAMPERED') ||
                          entry.status === 'FAILED'
                            ? 'text-red-400'
                            : 'text-emerald-400'
                        }
                      >
                        {entry.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-slate-400">No cryptographic operations recorded in this session yet.</p>
        )}
      </div>
    </aside>
  );
};
