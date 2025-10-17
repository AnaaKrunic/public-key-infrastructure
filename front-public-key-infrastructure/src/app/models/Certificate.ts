import { CertificateType } from './CertificateType';
import { CertificateStatus } from './CertificateStatus';

export interface Certificate {
  id: number;
  serialNumber: string;
  subjectCN: string;
  subjectO?: string;
  subjectOU?: string;
  subjectL?: string;
  subjectST?: string;
  subjectC?: string;
  subjectE?: string;
  subjectDN: string;
  issuerCN: string;
  issuerO?: string;
  issuerOU?: string;
  issuerL?: string;
  issuerST?: string;
  issuerC?: string;
  issuerE?: string;
  issuerDN: string;
  validFrom: string;
  validTo: string;
  certificateType: CertificateType;
  status: CertificateStatus;
  revocationReason?: string;
  revocationDate?: string;
  publicKey: string;
  certificateData: string;
  keyUsage?: string;
  extendedKeyUsage?: string;
  subjectAlternativeNames?: string;
  crlDistributionPoint?: string;
  canSign?: boolean;
  pathLength?: number;
  owner?: {
    id: number;
    email: string;
    firstName: string;
    lastName: string;
  };
  signedBy?: {
    id: number;
    email: string;
    firstName: string;
    lastName: string;
  };
  issuerCertificate?: {
    id: number;
    serialNumber: string;
    subjectCN: string;
  };
  signingCertificate?: {
    id: number;
    serialNumber: string;
    subjectCN: string;
  };
  template?: {
    id: number;
    name: string;
  };
  signingOrganization?: {
    id: number;
    name: string;
    contactEmail: string;
  };
  createdAt: string;
}

