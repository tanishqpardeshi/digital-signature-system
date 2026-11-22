import React from 'react';

interface CodeBlockProps {
  value: string;
  maxHeightClass?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ value, maxHeightClass = 'max-h-64' }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API may be unavailable in restricted contexts
    }
  };

  return (
    <div className="relative group rounded-md bg-[#111827] border border-slate-700/80 overflow-hidden">
      <button
        type="button"
        onClick={handleCopy}
        className="absolute top-2 right-2 px-2 py-1 text-xs rounded bg-slate-800/90 hover:bg-slate-700 text-slate-300 border border-slate-600/70 opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
      <pre
        className={`p-3 text-xs leading-relaxed text-slate-100 font-mono overflow-x-auto overflow-y-auto whitespace-pre-wrap break-all ${maxHeightClass}`}
      >
        <code>{value}</code>
      </pre>
    </div>
  );
};
