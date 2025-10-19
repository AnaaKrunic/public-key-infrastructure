export interface CreateCaUser {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  organization: string;
  initialSigningCertificateId: number;
}

