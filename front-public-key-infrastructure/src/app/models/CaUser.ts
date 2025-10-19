export interface CaUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  organization?: string; // Backend returns organization as string, not object
  minValidFrom?: string;
  maxValidUntil?: string;
}

