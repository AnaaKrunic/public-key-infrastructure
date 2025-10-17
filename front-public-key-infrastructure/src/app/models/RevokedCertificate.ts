import { RevocationReason } from './RevocationReason';

export interface RevokedCertificate {
  serialNumber: string;
  prettySerialNumber: string;
  issuedBy: string;
  issuedTo: string;
  decryptedCertificate: string;
  revocationReason: RevocationReason;
}

