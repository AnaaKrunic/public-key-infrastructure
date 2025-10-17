import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { RevokedCertificate } from '../../models/RevokedCertificate';

@Injectable({
  providedIn: 'root'
})
export class CrlService {
  private readonly API_BASE_URL = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {}

  // Get revoked certificates (public access)
  getRevokedCertificates(): Observable<RevokedCertificate[]> {
    return this.http.get<RevokedCertificate[]>(`${this.API_BASE_URL}/crl/web`);
  }

  // Download CRL file
  downloadCrl(): Observable<Blob> {
    return this.http.get(`${this.API_BASE_URL}/crl/`, { responseType: 'blob' });
  }
}
