import { CSRStatus } from './CSRStatus';

export interface CertificateRequest {
  id: string;
  submittedOn: string;
  commonName: string;
  organization: string;
  organizationalUnit: string;
  email: string;
  country: string;
  notBefore?: string;
  notAfter?: string;
  keyUsage?: string[];
  extendedKeyUsage?: string[];
  subjectAlternativeNames?: string[];
  issuerAlternativeNames?: string[];
  nameConstraints?: string;
  basicConstraints?: string;
  certificatePolicy?: string;
  status?: CSRStatus;
}

