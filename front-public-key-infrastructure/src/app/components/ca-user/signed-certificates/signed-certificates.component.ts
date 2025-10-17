import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { Certificate } from '../../../models/Certificate';

@Component({
  selector: 'app-signed-certificates',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="container">
      <h1>Certificates Signed by Me</h1>
      
      <div *ngIf="loading" class="loading">
        Loading certificates...
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="certificates.length > 0" class="certificates-table">
        <table>
          <thead>
            <tr>
              <th>Serial Number</th>
              <th>Subject</th>
              <th>Valid From</th>
              <th>Valid To</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let cert of certificates">
              <td>{{ cert.serialNumber }}</td>
              <td>{{ cert.subjectCN }}</td>
              <td>{{ formatDate(cert.validFrom) }}</td>
              <td>{{ formatDate(cert.validTo) }}</td>
              <td>
                <span [class]="'status-' + cert.status.toLowerCase()">
                  {{ cert.status }}
                </span>
              </td>
              <td>
                <button (click)="viewDetails(cert)" class="btn btn-sm btn-secondary">
                  Details
                </button>
                <button (click)="revokeCertificate(cert)" class="btn btn-sm btn-danger">
                  Revoke
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div *ngIf="!loading && !error && certificates.length === 0" class="no-data">
        No certificates found.
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 1200px;
      margin: 0 auto;
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

    .btn {
      padding: 6px 12px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      margin-right: 5px;
    }

    .btn-sm {
      padding: 4px 8px;
      font-size: 11px;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .status-active {
      color: #28a745;
      font-weight: bold;
    }

    .status-expired {
      color: #dc3545;
      font-weight: bold;
    }

    .status-revoked {
      color: #dc3545;
      font-weight: bold;
    }
  `]
})
export class SignedCertificatesComponent implements OnInit {
  certificates: Certificate[] = [];
  loading = false;
  error: string | null = null;

  constructor(private certificatesService: CertificatesService) {}

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.loading = true;
    this.error = null;

    this.certificatesService.getCertificatesSignedByMe().subscribe({
      next: (certs) => {
        this.certificates = certs;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to load certificates';
        this.loading = false;
        console.error('Error loading certificates:', err);
      }
    });
  }

  viewDetails(certificate: Certificate): void {
    // TODO: Implement certificate details modal
    console.log('View details for certificate:', certificate);
  }

  revokeCertificate(certificate: Certificate): void {
    if (confirm(`Are you sure you want to revoke certificate ${certificate.serialNumber}?`)) {
      // TODO: Implement certificate revocation
      console.log('Revoke certificate:', certificate);
    }
  }

  formatDate(dateString: string): string {
    return new Date(dateString).toLocaleDateString();
  }
}
