import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class MfaService {
  private apiUrl = 'http://localhost:8080/api';

  constructor(private http: HttpClient) { }

  getMfaStatus(email: string): Observable<{mfaEnabled: boolean}> {
    const params = new HttpParams().set('email', email);
    return this.http.get<{mfaEnabled: boolean}>(`${this.apiUrl}/mfa/status`, { params });
  }

  enableMfa(email: string): Observable<{qrImage: string, secretKey: string}> {
    const params = new HttpParams().set('email', email);
    return this.http.post<{qrImage: string, secretKey: string}>(`${this.apiUrl}/mfa/enable`, null, { params });
  }

  verifyMfa(email: string, code: string): Observable<any> {
    const params = new HttpParams()
      .set('email', email)
      .set('code', code);
    return this.http.post<any>(`${this.apiUrl}/mfa/verify`, null, { params });
  }
}