export interface CreateCertificateRequest {
  signingOrganization: string;
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
}

