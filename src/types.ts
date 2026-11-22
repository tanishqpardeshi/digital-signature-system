export type AlgorithmType = 'Ed25519' | 'RSA-2048';
export type PayloadType = 'text' | 'file';

export interface KeyPair {
  algorithm: AlgorithmType;
  private_pem: string;
  public_pem: string;
  fingerprint_sha256: string;
  encrypted: boolean;
  created_at: string;
}

export interface SignatureBundle {
  algorithm: AlgorithmType;
  signature_b64: string;
  payload_sha256: string;
  public_key_fingerprint: string;
  signed_at: string;
  payload_type: PayloadType;
  filename: string | null;
}

export interface VerificationResult {
  is_valid: boolean;
  algorithm: string;
  payload_sha256: string;
  public_key_fingerprint: string;
  reason: string;
}

export interface ActivityLogEntry {
  timeUtc: string;
  action: string;
  algorithm: string;
  keyFingerprint: string;
  status: string;
}
