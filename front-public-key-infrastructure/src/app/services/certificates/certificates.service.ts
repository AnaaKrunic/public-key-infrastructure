import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Certificate } from '../../models/Certificate';
import { IssueCertificateRequest } from '../../models/IssueCertificateRequest';
import { DownloadCertificateRequest } from '../../models/DownloadCertificateRequest';
import { RevokeCertificateRequest } from '../../models/RevokeCertificateRequest';
import { CreateCaUser } from '../../models/CreateCaUser';
import { CaUser } from '../../models/CaUser';

@Injectable({
  providedIn: 'root'
})
export class CertificatesService {
  private readonly API_BASE_URL = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {}

  // Get all certificates
  getAllCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-all`);
  }

  // Get all valid signing certificates
  getAllValidSigningCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-all-valid-signing`);
  }

  // Get my certificates
  getMyCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-my-certificates`);
  }

  // Get my valid certificates
  getMyValidCertificates(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-my-valid-certificates`);
  }

  // Get certificates signed by me (for CA users)
  getCertificatesSignedByMe(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-certificates-signed-by-me`);
  }

  // Issue a certificate
  issueCertificate(request: IssueCertificateRequest): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/certificates/issue`, request);
  }

  // Download certificate
  downloadCertificate(request: DownloadCertificateRequest): Observable<Blob> {
    return this.http.post(`${this.API_BASE_URL}/certificates/download`, request, {
      responseType: 'blob'
    });
  }

  // Download certificate in specific format
  downloadCertificateInFormat(serialNumber: string, format: string = 'PEM', password?: string): Observable<Blob> {
    let url = `${this.API_BASE_URL}/certificates/download/${serialNumber}?format=${format}`;
    if (password) {
      url += `&password=${encodeURIComponent(password)}`;
    }
    return this.http.get(url, { responseType: 'blob' });
  }

  // Revoke certificate
  revokeCertificate(request: RevokeCertificateRequest): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/crl/revoke`, request);
  }

  // Add certificate to CA user (Admin only)
  addCertificateToCaUser(caUserId: string, certificateSerialNumber: string): Observable<any> {
    return this.http.put(`${this.API_BASE_URL}/certificates/add-certificate-to-ca-user`, {
      caUserId,
      newCertificateSerialNumber: certificateSerialNumber
    });
  }

  // Get signing certificates that CA user doesn't have (Admin only)
  getSigningCertificatesCaUserDoesntHave(caUserId: string): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(`${this.API_BASE_URL}/certificates/get-signing-ca-doesnt-have/${caUserId}`);
  }
}
