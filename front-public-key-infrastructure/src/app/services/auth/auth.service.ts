import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
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
          // Extract token from response object
          const token = response.accessToken;
          
          // Store the token and create auth state
          const authState: AuthState = {
            accessToken: token,
            accessExpiresAt: this.calculateTokenExpiry(),
            refreshToken: null, // Backend doesn't return refresh token in this implementation
            refreshExpiresAt: null,
            user: null // Will be fetched separately
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
    // JWT tokens typically expire in 1 hour, so we'll set expiry to 1 hour from now
    const expiryTime = new Date();
    expiryTime.setHours(expiryTime.getHours() + 1);
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

  // Method to refresh token (if backend supports it)
  refreshToken(): Observable<string> {
    // For now, we'll just return the current token
    // In a real implementation, you'd call a refresh endpoint
    const currentToken = this.getToken();
    if (currentToken) {
      return of(currentToken);
    }
    throw new Error('No token to refresh');
  }
}