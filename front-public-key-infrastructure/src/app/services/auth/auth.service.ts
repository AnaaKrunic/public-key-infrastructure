import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of, throwError } from 'rxjs';
import { map, catchError, tap, switchMap } from 'rxjs/operators';
import { LoginRequest } from '../../models/LoginRequest';
import { RegisterRequest } from '../../models/RegisterRequest';
import { BasicUser } from '../../models/BasicUser';
import { AuthState } from '../../models/AuthState';
import { Role } from '../../models/Role';

// Export LoginDTO for backward compatibility
export interface LoginDTO {
  email: string;
  password: string;
  mfaCode?: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_BASE_URL = 'http://localhost:8080/api';
  private readonly AUTH_STORAGE_KEY = 'pki_auth_state';

  private authStateSubject = new BehaviorSubject<AuthState | null>(null);
  public authState$ = this.authStateSubject.asObservable();

  private userSubject = new BehaviorSubject<BasicUser | null>(null);
  public user$ = this.userSubject.asObservable();

  private roleSubject = new BehaviorSubject<Role | null>(null);
  public role$ = this.roleSubject.asObservable();

  private isLoggedInSubject = new BehaviorSubject<boolean>(false);
  public isLoggedIn$ = this.isLoggedInSubject.asObservable();

  constructor(private http: HttpClient) {
    this.initializeAuthState();
  }

  private initializeAuthState(): void {
    const storedState = localStorage.getItem(this.AUTH_STORAGE_KEY);
    if (storedState) {
      try {
        const authState: AuthState = JSON.parse(storedState);
        this.authStateSubject.next(authState);
        this.isLoggedInSubject.next(!!authState.accessToken);
        
        // If we have a token but no user data, fetch it
        if (authState.accessToken && !authState.user) {
          this.getCurrentUser().subscribe({
            next: (user) => {
              this.userSubject.next(user);
              this.roleSubject.next(user.role);
            },
            error: (error) => {
              this.clearAuthState();
            }
          });
        } else {
          this.userSubject.next(authState.user);
          this.roleSubject.next(authState.user?.role || null);
        }
      } catch (error) {
        this.clearAuthState();
      }
    }
  }

  login(loginRequest: LoginRequest): Observable<any> {
    return this.http.post<any>(`${this.API_BASE_URL}/auth/login`, loginRequest)
      .pipe(
        tap((response: any) => {
          // Expecting accessToken, refreshToken, expiresIn (seconds for access)
          const accessToken: string = response.accessToken;
          const refreshToken: string = response.refreshToken;
          const expiresInSec: number = response.expiresIn ?? (15 * 60);

          const now = new Date().getTime();
          const accessExpiresAt = new Date(now + expiresInSec * 1000).toISOString();
          // Align with backend 7 days refresh policy
          const refreshExpiresAt = new Date(now + 7 * 24 * 60 * 60 * 1000).toISOString();

          const authState: AuthState = {
            accessToken: accessToken,
            accessExpiresAt: accessExpiresAt,
            refreshToken: refreshToken,
            refreshExpiresAt: refreshExpiresAt,
            user: null
          };

          this.authStateSubject.next(authState);
          this.isLoggedInSubject.next(true);
          localStorage.setItem(this.AUTH_STORAGE_KEY, JSON.stringify(authState));
        }),
        switchMap((response: any) => {
          // Fetch user details and return the user data
          return this.getCurrentUser().pipe(
            map((user) => {
              return { ...response, user };
            }),
            catchError((error) => {
              // Return the response even if getCurrentUser fails
              return of({ ...response, user: null });
            })
          );
        })
      );
  }

  register(registerRequest: RegisterRequest): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/auth/register`, registerRequest);
  }

  getCurrentUser(): Observable<BasicUser> {
    return this.http.get<any>(`${this.API_BASE_URL}/users/me`)
      .pipe(
        map(response => {
          const user: BasicUser = {
            id: response.id.toString(),
            role: response.role,
            name: response.firstName,
            surname: response.lastName,
            email: response.email,
            organization: response.organization
          };
          
          this.userSubject.next(user);
          this.roleSubject.next(user.role);
          
          // Update stored auth state with user info
          const currentState = this.authStateSubject.value;
          if (currentState) {
            const updatedState: AuthState = {
              ...currentState,
              user: user
            };
            this.authStateSubject.next(updatedState);
            localStorage.setItem(this.AUTH_STORAGE_KEY, JSON.stringify(updatedState));
          }
          
          return user;
        })
      );
  }

  logout(): void {
    this.clearAuthState();
  }

  private clearAuthState(): void {
    this.authStateSubject.next(null);
    this.userSubject.next(null);
    this.roleSubject.next(null);
    this.isLoggedInSubject.next(false);
    localStorage.removeItem(this.AUTH_STORAGE_KEY);
  }

  getToken(): string | null {
    return this.authStateSubject.value?.accessToken || null;
  }

  getCurrentRole(): Role | null {
    return this.roleSubject.value;
  }

  get isLoggedIn(): boolean {
    return this.isLoggedInSubject.value;
  }

  get userRole(): Role | null {
    return this.roleSubject.value;
  }

  get userEmail(): string | null {
    return this.userSubject.value?.email || null;
  }

  get accessToken(): string | null {
    return this.authStateSubject.value?.accessToken || null;
  }

  hasRole(role: Role): boolean {
    return this.getCurrentRole() === role;
  }

  hasAnyRole(roles: Role[]): boolean {
    const currentRole = this.getCurrentRole();
    return currentRole ? roles.includes(currentRole) : false;
  }

  private calculateTokenExpiry(): string {
    // Keep utility, but align with backend default (15 minutes)
    const expiryTime = new Date();
    expiryTime.setMinutes(expiryTime.getMinutes() + 15);
    return expiryTime.toISOString();
  }

  // Method to check if token is expired (basic implementation)
  isTokenExpired(): boolean {
    const authState = this.authStateSubject.value;
    if (!authState?.accessExpiresAt) {
      return true;
    }
    
    const expiryTime = new Date(authState.accessExpiresAt);
    return new Date() >= expiryTime;
  }

  // Method to refresh token using backend rotation
  refreshToken(): Observable<string> {
    const currentState = this.authStateSubject.value;
    if (!currentState?.refreshToken) {
      return throwError(() => new Error('No refresh token available'));
    }

    // Optional: check refresh token local expiry hint
    if (currentState.refreshExpiresAt && new Date(currentState.refreshExpiresAt) <= new Date()) {
      return throwError(() => new Error('Refresh token expired'));
    }

    return this.http.post<any>(`${this.API_BASE_URL}/auth/refresh`, { refreshToken: currentState.refreshToken })
      .pipe(
        tap((response: any) => {
          const accessToken: string = response.accessToken;
          const refreshToken: string = response.refreshToken;
          const expiresInSec: number = response.expiresIn ?? (15 * 60);

          const now = new Date().getTime();
          const accessExpiresAt = new Date(now + expiresInSec * 1000).toISOString();
          const refreshExpiresAt = new Date(now + 7 * 24 * 60 * 60 * 1000).toISOString();

          const updatedState: AuthState = {
            ...currentState,
            accessToken: accessToken,
            accessExpiresAt: accessExpiresAt,
            refreshToken: refreshToken,
            refreshExpiresAt: refreshExpiresAt
          };

          this.authStateSubject.next(updatedState);
          localStorage.setItem(this.AUTH_STORAGE_KEY, JSON.stringify(updatedState));
        }),
        map((response: any) => response.accessToken)
      );
  }
}