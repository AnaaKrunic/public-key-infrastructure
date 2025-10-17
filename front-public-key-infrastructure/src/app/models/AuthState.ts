import { BasicUser } from './BasicUser';

export interface AuthState {
  accessToken: string | null;
  accessExpiresAt: string | null;
  refreshToken: string | null;
  refreshExpiresAt: string | null;
  user: BasicUser | null;
}

