/**
 * Basic CA certificate information.
 * Contains only essential information for EE users to select a CA.
 */
export interface BasicCACertificate {
  serialNumber: string;
  commonName: string;
  organization: string;
  organizationalUnit: string;
}

