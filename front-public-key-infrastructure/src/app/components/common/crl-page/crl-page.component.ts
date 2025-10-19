import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CrlService } from '../../../services/crl/crl.service';
import { RevokedCertificate } from '../../../models/RevokedCertificate';

@Component({
  selector: 'app-crl-page',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="container">
      <h1>Certificate Revocation List (CRL)</h1>
      
      <div class="actions">
        <button (click)="downloadCrl()" class="btn btn-primary">
          Download CRL File
        </button>
      </div>

      <div *ngIf="loading" class="loading">
        Loading revoked certificates...
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="revokedCertificates.length > 0" class="certificates-table">
        <h2>Revoked Certificates</h2>
        <table>
          <thead>
            <tr>
              <th>Serial Number</th>
              <th>Issued To</th>
              <th>Issued By</th>
              <th>Revocation Reason</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let cert of revokedCertificates">
              <td>{{ cert.prettySerialNumber }}</td>
              <td>{{ cert.issuedTo }}</td>
              <td>{{ cert.issuedBy }}</td>
              <td>{{ cert.revocationReason }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div *ngIf="!loading && !error && revokedCertificates.length === 0" class="no-data">
        No revoked certificates found.
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 1200px;
      margin: 0 auto;
    }

    .actions {
      margin-bottom: 20px;
    }

    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }

    .btn-primary {
      background-color: #007bff;
      color: white;
    }

    .btn-primary:hover {
      background-color: #0056b3;
    }

    .loading, .error, .no-data {
      text-align: center;
      padding: 20px;
      font-size: 16px;
    }

    .error {
      color: #dc3545;
    }

    .certificates-table {
      margin-top: 20px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
    }

    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }

    th {
      background-color: #f8f9fa;
      font-weight: 600;
    }

    tr:hover {
      background-color: #f5f5f5;
    }
  `]
})
export class CrlPageComponent implements OnInit {
  revokedCertificates: RevokedCertificate[] = [];
  loading = false;
  error: string | null = null;

  constructor(private crlService: CrlService) {}

  ngOnInit(): void {
    this.loadRevokedCertificates();
  }

  loadRevokedCertificates(): void {
    this.loading = true;
    this.error = null;

    this.crlService.getRevokedCertificates().subscribe({
      next: (certificates) => {
        this.revokedCertificates = certificates;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to load revoked certificates';
        this.loading = false;
        console.error('Error loading revoked certificates:', err);
      }
    });
  }

  downloadCrl(): void {
    this.crlService.downloadCrl().subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'crl.crl';
        link.click();
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Error downloading CRL:', err);
        alert('Failed to download CRL file');
      }
    });
  }
}
