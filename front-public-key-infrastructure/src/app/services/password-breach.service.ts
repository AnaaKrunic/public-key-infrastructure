import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface PasswordBreachResponse {
  isSafe: boolean;
  breachCount: number;
  message: string;
}

@Injectable({
  providedIn: 'root'
})
export class PasswordBreachService {
  private readonly API_URL = 'https://localhost:8443/api/auth';

  constructor(private http: HttpClient) {}

  checkPasswordBreach(password: string): Observable<PasswordBreachResponse> {
    return this.http.post<PasswordBreachResponse>(`${this.API_URL}/check-password-breach`, {
      password: password
    });
  }
}
