import crypto from 'node:crypto';
import type {
  AlgorithmType,
  KeyPair,
  PayloadType,
  SignatureBundle,
  VerificationResult,
} from '../types.ts';

export const SUPPORTED_ALGORITHMS: readonly AlgorithmType[] = ['Ed25519', 'RSA-2048'];

function utcNowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function computeSha256Hex(data: Buffer): string {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError('data must be a Buffer.');
  }
  return crypto.createHash('sha256').update(data).digest('hex');
}

function formatColonHexGroups(hexDigest: string, groupSize = 4): string {
  const upper = hexDigest.toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < upper.length; i += groupSize) {
    groups.push(upper.slice(i, i + groupSize));
  }
  return groups.join(':');
}

export function serializeSignatureBundleCanonical(bundle: SignatureBundle): string {
  const ordered: SignatureBundle = {
    algorithm: bundle.algorithm,
    filename: bundle.filename ?? null,
    payload_sha256: bundle.payload_sha256,
    payload_type: bundle.payload_type,
    public_key_fingerprint: bundle.public_key_fingerprint,
    signature_b64: bundle.signature_b64,
    signed_at: bundle.signed_at,
  };
  return JSON.stringify(ordered, null, 2);
}

export function parseSignatureBundle(rawJson: string): SignatureBundle {
  if (typeof rawJson !== 'string' || !rawJson.trim()) {
    throw new Error('SignatureBundle JSON input cannot be empty.');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Malformed JSON';
    throw new Error(`Malformed JSON in signature bundle: ${msg}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('SignatureBundle JSON root must be an object.');
  }

  const record = parsed as Record<string, unknown>;
  const requiredFields = [
    'algorithm',
    'signature_b64',
    'payload_sha256',
    'public_key_fingerprint',
    'signed_at',
    'payload_type',
  ] as const;

  const missing = requiredFields.filter(
    (field) => !(field in record) || record[field] === null || record[field] === undefined || record[field] === ''
  );
  if (missing.length > 0) {
    throw new Error(`Missing required field(s) in SignatureBundle: ${missing.join(', ')}`);
  }

  const algorithm = record.algorithm;
  if (algorithm !== 'Ed25519' && algorithm !== 'RSA-2048') {
    throw new Error(`Unsupported algorithm in SignatureBundle: ${JSON.stringify(algorithm)}`);
  }

  const payloadType = record.payload_type;
  if (payloadType !== 'text' && payloadType !== 'file') {
    throw new Error(`Invalid payload_type in SignatureBundle: ${JSON.stringify(payloadType)}`);
  }

  const filename = record.filename ?? null;
  if (filename !== null && typeof filename !== 'string') {
    throw new Error("Field 'filename' must be a string or null.");
  }

  return {
    algorithm,
    signature_b64: String(record.signature_b64),
    payload_sha256: String(record.payload_sha256),
    public_key_fingerprint: String(record.public_key_fingerprint),
    signed_at: String(record.signed_at),
    payload_type: payloadType,
    filename,
  };
}

export function publicKeyFingerprint(publicPem: string): string {
  if (typeof publicPem !== 'string' || !publicPem.trim()) {
    throw new Error('Public key PEM cannot be empty.');
  }

  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({ key: publicPem, format: 'pem' });
  } catch {
    throw new Error('Invalid or unsupported public key PEM format.');
  }

  const derBytes = publicKey.export({ type: 'spki', format: 'der' });
  const digestHex = crypto.createHash('sha256').update(derBytes).digest('hex');
  return formatColonHexGroups(digestHex, 4);
}

export function generateKeypair(algorithm: AlgorithmType = 'Ed25519', passphrase = ''): KeyPair {
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error(`Unsupported algorithm ${JSON.stringify(algorithm)}. Choose from ${SUPPORTED_ALGORITHMS.join(', ')}.`);
  }

  const isEncrypted = Boolean(passphrase);
  const privateKeyEncoding = isEncrypted
    ? {
        type: 'pkcs8' as const,
        format: 'pem' as const,
        cipher: 'aes-256-cbc' as const,
        passphrase,
      }
    : {
        type: 'pkcs8' as const,
        format: 'pem' as const,
      };

  let privatePem: string;
  let publicPem: string;

  if (algorithm === 'Ed25519') {
    const pair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding,
    });
    privatePem = pair.privateKey;
    publicPem = pair.publicKey;
  } else {
    const pair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding,
    });
    privatePem = pair.privateKey;
    publicPem = pair.publicKey;
  }

  const fingerprint = publicKeyFingerprint(publicPem);

  return {
    algorithm,
    private_pem: privatePem,
    public_pem: publicPem,
    fingerprint_sha256: fingerprint,
    encrypted: isEncrypted,
    created_at: utcNowIso(),
  };
}

export function signBytes(
  privatePem: string,
  data: Buffer,
  passphrase = '',
  payloadType: PayloadType = 'text',
  filename: string | null = null
): SignatureBundle {
  if (typeof privatePem !== 'string' || !privatePem.trim()) {
    throw new Error('Private key PEM cannot be empty.');
  }
  if (!Buffer.isBuffer(data)) {
    throw new TypeError('Payload data must be raw bytes.');
  }
  if (payloadType !== 'text' && payloadType !== 'file') {
    throw new Error("payload_type must be either 'text' or 'file'.");
  }

  const isPemEncrypted =
    privatePem.includes('BEGIN ENCRYPTED PRIVATE KEY') ||
    privatePem.includes('Proc-Type: 4,ENCRYPTED');

  if (isPemEncrypted && !passphrase) {
    throw new Error('Passphrase mismatch when loading private key: Password was not provided for encrypted private key.');
  }
  if (!isPemEncrypted && passphrase) {
    throw new Error('Passphrase mismatch when loading private key: Password was given but private key is not encrypted.');
  }

  let privateKey: crypto.KeyObject;
  try {
    privateKey = crypto.createPrivateKey({
      key: privatePem,
      format: 'pem',
      ...(passphrase ? { passphrase } : {}),
    });
  } catch {
    throw new Error('Failed to load private key PEM. Ensure the PEM is valid and the passphrase is correct.');
  }

  let algorithm: AlgorithmType;
  let signature: Buffer;

  if (privateKey.asymmetricKeyType === 'ed25519') {
    algorithm = 'Ed25519';
    signature = crypto.sign(null, data, privateKey);
  } else if (privateKey.asymmetricKeyType === 'rsa' || privateKey.asymmetricKeyType === 'rsa-pss') {
    algorithm = 'RSA-2048';
    signature = crypto.sign('sha256', data, {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
    });
  } else {
    throw new Error(
      `Unsupported private key algorithm: ${privateKey.asymmetricKeyType ?? 'unknown'}. Only Ed25519 and RSA are supported.`
    );
  }

  const publicKey = crypto.createPublicKey(privateKey);
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

  return {
    algorithm,
    signature_b64: signature.toString('base64'),
    payload_sha256: computeSha256Hex(data),
    public_key_fingerprint: publicKeyFingerprint(publicPem),
    signed_at: utcNowIso(),
    payload_type: payloadType,
    filename,
  };
}

export function verifyBytes(publicPem: string, data: Buffer, signatureB64: string): VerificationResult {
  const rawBytes = Buffer.isBuffer(data) ? data : Buffer.alloc(0);
  const payloadHash = computeSha256Hex(rawBytes);

  if (typeof publicPem !== 'string' || !publicPem.trim()) {
    return {
      is_valid: false,
      algorithm: 'Unknown',
      payload_sha256: payloadHash,
      public_key_fingerprint: 'N/A',
      reason: 'Public key PEM is empty.',
    };
  }

  if (typeof signatureB64 !== 'string' || !signatureB64.trim()) {
    return {
      is_valid: false,
      algorithm: 'Unknown',
      payload_sha256: payloadHash,
      public_key_fingerprint: 'N/A',
      reason: 'Signature Base64 input is empty.',
    };
  }

  let publicKey: crypto.KeyObject;
  let fingerprint: string;
  try {
    publicKey = crypto.createPublicKey({ key: publicPem, format: 'pem' });
    const derBytes = publicKey.export({ type: 'spki', format: 'der' });
    const digestHex = crypto.createHash('sha256').update(derBytes).digest('hex');
    fingerprint = formatColonHexGroups(digestHex, 4);
  } catch {
    return {
      is_valid: false,
      algorithm: 'Unknown',
      payload_sha256: payloadHash,
      public_key_fingerprint: 'N/A',
      reason: 'Invalid or corrupted Public Key PEM format.',
    };
  }

  let algorithm: string;
  if (publicKey.asymmetricKeyType === 'ed25519') {
    algorithm = 'Ed25519';
  } else if (publicKey.asymmetricKeyType === 'rsa' || publicKey.asymmetricKeyType === 'rsa-pss') {
    algorithm = 'RSA-2048';
  } else {
    const keyType = publicKey.asymmetricKeyType ?? 'Unknown';
    return {
      is_valid: false,
      algorithm: keyType,
      payload_sha256: payloadHash,
      public_key_fingerprint: fingerprint,
      reason: `Unsupported public key type: ${keyType}.`,
    };
  }

  const cleanedB64 = signatureB64.trim().replace(/\s+/g, '');
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (!cleanedB64 || !base64Regex.test(cleanedB64)) {
    return {
      is_valid: false,
      algorithm,
      payload_sha256: payloadHash,
      public_key_fingerprint: fingerprint,
      reason: 'Malformed Base64 encoding in signature.',
    };
  }

  const signatureBytes = Buffer.from(cleanedB64, 'base64');
  if (signatureBytes.length === 0) {
    return {
      is_valid: false,
      algorithm,
      payload_sha256: payloadHash,
      public_key_fingerprint: fingerprint,
      reason: 'Decoded signature is empty.',
    };
  }

  try {
    let valid = false;
    if (publicKey.asymmetricKeyType === 'ed25519') {
      valid = crypto.verify(null, rawBytes, publicKey, signatureBytes);
    } else {
      valid = crypto.verify(
        'sha256',
        rawBytes,
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
        },
        signatureBytes
      );
    }

    if (!valid) {
      return {
        is_valid: false,
        algorithm,
        payload_sha256: payloadHash,
        public_key_fingerprint: fingerprint,
        reason:
          'Cryptographic verification failed: payload was modified, signature was corrupted, or public key does not match the signer.',
      };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      is_valid: false,
      algorithm,
      payload_sha256: payloadHash,
      public_key_fingerprint: fingerprint,
      reason: `Verification error: ${msg}`,
    };
  }

  return {
    is_valid: true,
    algorithm,
    payload_sha256: payloadHash,
    public_key_fingerprint: fingerprint,
    reason: 'Cryptographic signature verified: authenticity and payload integrity confirmed.',
  };
}
