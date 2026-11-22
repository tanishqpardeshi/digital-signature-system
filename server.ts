import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import {
  generateKeypair,
  parseSignatureBundle,
  serializeSignatureBundleCanonical,
  signBytes,
  verifyBytes,
} from './src/server/cryptoCore.ts';
import type { AlgorithmType, PayloadType } from './src/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SAMPLE_INVOICE_TEXT =
  'INVOICE #INV-2026-0842\n' +
  'From: Aegis Cloud Security Ltd.\n' +
  'To: Meridian Financial Holdings\n' +
  'Amount Due: $48,500.00 USD\n' +
  'Settlement IBAN: DE89-3704-0044-0532-0130-00\n' +
  'Authorized By: Chief Information Security Officer\n' +
  'Terms: Net-15 Wire Transfer — Immutable Cryptographic Audit Record';

async function startServer(): Promise<void> {
  const app = express();
  app.use(express.json({ limit: '50mb' }));

  app.post('/api/keypair', (req, res) => {
    try {
      const body = req.body as { algorithm?: string; passphrase?: string };
      const algorithm: AlgorithmType = body?.algorithm === 'RSA-2048' ? 'RSA-2048' : 'Ed25519';
      const passphrase = typeof body?.passphrase === 'string' ? body.passphrase : '';
      const keypair = generateKeypair(algorithm, passphrase);
      res.json(keypair);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Key generation failed.';
      res.status(400).json({ error: msg });
    }
  });

  app.post('/api/sign', (req, res) => {
    try {
      const body = req.body as {
        private_pem?: string;
        data_b64?: string;
        passphrase?: string;
        payload_type?: string;
        filename?: string | null;
      };
      const privatePem = typeof body?.private_pem === 'string' ? body.private_pem : '';
      const dataB64 = typeof body?.data_b64 === 'string' ? body.data_b64 : '';
      const passphrase = typeof body?.passphrase === 'string' ? body.passphrase : '';
      const payloadType: PayloadType = body?.payload_type === 'file' ? 'file' : 'text';
      const filename = typeof body?.filename === 'string' ? body.filename : null;

      if (!privatePem.trim()) {
        res.status(400).json({ error: 'Please provide a valid Private Key before signing.' });
        return;
      }

      const dataBuffer = Buffer.from(dataB64, 'base64');
      if (dataBuffer.length === 0) {
        res.status(400).json({ error: 'Payload cannot be empty. Enter text or upload a non-empty file.' });
        return;
      }

      const bundle = signBytes(privatePem, dataBuffer, passphrase, payloadType, filename);
      const canonicalJson = serializeSignatureBundleCanonical(bundle);
      res.json({ bundle, canonical_json: canonicalJson });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Signing failed.';
      res.status(400).json({ error: msg });
    }
  });

  app.post('/api/verify', (req, res) => {
    try {
      const body = req.body as {
        public_pem?: string;
        data_b64?: string;
        signature_b64?: string;
      };
      const publicPem = typeof body?.public_pem === 'string' ? body.public_pem : '';
      const dataB64 = typeof body?.data_b64 === 'string' ? body.data_b64 : '';
      const signatureB64 = typeof body?.signature_b64 === 'string' ? body.signature_b64 : '';

      const dataBuffer = Buffer.from(dataB64, 'base64');
      const result = verifyBytes(publicPem, dataBuffer, signatureB64);
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Verification failed.';
      res.status(400).json({ error: msg });
    }
  });

  app.post('/api/bundle/parse', (req, res) => {
    try {
      const body = req.body as { raw_json?: string };
      const rawJson = typeof body?.raw_json === 'string' ? body.raw_json : '';
      const bundle = parseSignatureBundle(rawJson);
      res.json({ bundle });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Invalid .sig.json bundle.';
      res.status(400).json({ error: msg });
    }
  });

  app.post('/api/quick-start', (_req, res) => {
    try {
      const keypair = generateKeypair('Ed25519', '');
      const payloadBuffer = Buffer.from(SAMPLE_INVOICE_TEXT, 'utf-8');
      const bundle = signBytes(keypair.private_pem, payloadBuffer, '', 'text', 'invoice_2026_0842.txt');
      const canonicalJson = serializeSignatureBundleCanonical(bundle);
      const verification = verifyBytes(keypair.public_pem, payloadBuffer, bundle.signature_b64);
      res.json({
        keypair,
        bundle,
        canonical_json: canonicalJson,
        verification,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Quick-Start initialization failed.';
      res.status(500).json({ error: msg });
    }
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.join(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`Digital Signature Verification System running on http://0.0.0.0:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
