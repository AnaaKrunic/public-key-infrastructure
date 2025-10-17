export interface LoginRequest {
  email: string;
  password: string;
  mfaCode?: string;
}

