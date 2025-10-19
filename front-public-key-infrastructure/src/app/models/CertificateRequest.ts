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
  status: CSRStatus; // Make status required to match backend CSRDTO
  
  // Additional fields from CSRDTO (for compatibility)
  subjectCN?: string; // Alternative to commonName
  subjectO?: string; // Alternative to organization
  subjectOU?: string; // Alternative to organizationalUnit
  subjectE?: string; // Alternative to email
  subjectC?: string; // Alternative to country
  createdAt?: string; // Alternative to submittedOn
  rejectionReason?: string;
  processedAt?: string;
  requester?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
  };
  selectedCA?: {
    id: string;
    serialNumber: string;
    subjectCN: string;
  };
  processedBy?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
  };
}

