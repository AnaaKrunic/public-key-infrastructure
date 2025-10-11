import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';

export interface UserRegistrationDTO {
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
  organization: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_URL = 'http://localhost:8080/api/auth';
  private accessTokenSubject = new BehaviorSubject(this.getStoredAccessToken());
  private refreshTokenSubject = new BehaviorSubject(this.getStoredRefreshToken());

  public accessToken$ = this.accessTokenSubject.asObservable();
  public refreshToken$ = this.refreshTokenSubject.asObservable();

  constructor(private http: HttpClient) {}

  register(userData: UserRegistrationDTO): Observable<any> {
    return this.http.post<any>(`${this.API_URL}/register`, userData);
  }

  login(credentials: LoginDTO): Observable<any> {
    return this.http.post<any>(`${this.API_URL}/login`, credentials)
      .pipe(
        tap((response: any) => {
          // Store only access token for now (refresh token not implemented yet)
          const accessToken = response.accessToken;
          this.storeTokens(accessToken, null);
          this.accessTokenSubject.next(accessToken);
          this.refreshTokenSubject.next(null);
        })
      );
  }

  activateAccount(token: string): Observable<any> {
    return this.http.get<any>(`${this.API_URL}/activate?token=${token}`);
  }

  logout(): void {
    this.clearTokens();
    this.accessTokenSubject.next(null);
    this.refreshTokenSubject.next(null);
  }

  isAuthenticated(): boolean {
    return !!this.getStoredAccessToken();
  }

  getAccessToken(): string | null {
    return this.accessTokenSubject.value;
  }

  getRefreshToken(): string | null {
    return this.refreshTokenSubject.value;
  }

  private storeTokens(accessToken: string, refreshToken: string | null): void {
    localStorage.setItem('accessToken', accessToken);
    if (refreshToken) {
      localStorage.setItem('refreshToken', refreshToken);
    }
  }

  private getStoredAccessToken(): string | null {
    return localStorage.getItem('accessToken');
  }

  private getStoredRefreshToken(): string | null {
    return localStorage.getItem('refreshToken');
  }

  private clearTokens(): void {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  }

  getAuthHeaders(): HttpHeaders {
    const token = this.getAccessToken();
    return new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    });
  }

  getUserEmail(): string {
    const token = this.getAccessToken();
    if (!token) {
      console.log('No access token found');
      return '';
    }
    
    try {
      // Decode JWT token to get email from 'sub' field
      const payload = JSON.parse(atob(token.split('.')[1]));
      console.log('JWT payload:', payload);
      return payload.sub || '';
    } catch (error) {
      console.error('Error decoding JWT token:', error);
      return '';
    }
  }
}
