import { RevocationReason } from './RevocationReason';

export interface RevokeCertificateRequest {
  serialNumber: string;
  revocationReason: RevocationReason;
}

