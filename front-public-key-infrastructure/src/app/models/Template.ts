export interface Template {
  id: number;
  name: string;
  caIssuerSerialNumber: string;
  cnRegex: string;
  sanRegex: string;
  ttl: number;
  keyUsage: string;
  extendedKeyUsage: string;
  createdBy: {
    id: number;
    email: string;
    firstName: string;
    lastName: string;
  };
  createdAt: string;
  updatedAt?: string;
}

export interface CreateTemplateDTO {
  name: string;
  caIssuerSerialNumber: string;
  cnRegex: string;
  sanRegex: string;
  ttl: number;
  keyUsage: string;
  extendedKeyUsage: string;
}

export interface UpdateTemplateDTO {
  name: string;
  cnRegex: string;
  sanRegex: string;
  ttl: number;
  keyUsage: string;
  extendedKeyUsage: string;
}

export interface TemplateValidationResult {
  isValid: boolean;
  error?: string;
}
