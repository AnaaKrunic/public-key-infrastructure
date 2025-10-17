export interface CaUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  organization: string;
  minValidFrom?: string;
  maxValidUntil?: string;
}

