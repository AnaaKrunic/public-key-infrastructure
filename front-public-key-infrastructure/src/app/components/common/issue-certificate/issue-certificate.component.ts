import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { Certificate } from '../../../models/Certificate';
import { IssueCertificateRequest } from '../../../models/IssueCertificateRequest';

@Component({
  selector: 'app-issue-certificate',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h1>Issue Certificate</h1>
      
      <form (ngSubmit)="onSubmit()" #certificateForm="ngForm">
        <div class="form-group">
          <label for="signingCertificate">Signing Certificate *</label>
          <select 
            id="signingCertificate" 
            name="signingCertificate" 
            [(ngModel)]="request.signingCertificate" 
            required
            class="form-control">
            <option value="">Select a signing certificate</option>
            <option *ngFor="let cert of signingCertificates" [value]="cert.serialNumber">
              {{ cert.subjectCN }} ({{ cert.serialNumber }})
            </option>
          </select>
        </div>

        <div class="form-group">
          <label for="commonName">Common Name *</label>
          <input 
            type="text" 
            id="commonName" 
            name="commonName" 
            [(ngModel)]="request.commonName" 
            required
            class="form-control">
        </div>

        <div class="form-group">
          <label for="organization">Organization *</label>
          <input 
            type="text" 
            id="organization" 
            name="organization" 
            [(ngModel)]="request.organization" 
            required
            class="form-control">
        </div>

        <div class="form-group">
          <label for="organizationalUnit">Organizational Unit *</label>
          <input 
            type="text" 
            id="organizationalUnit" 
            name="organizationalUnit" 
            [(ngModel)]="request.organizationalUnit" 
            required
            class="form-control">
        </div>

        <div class="form-group">
          <label for="email">Email *</label>
          <input 
            type="email" 
            id="email" 
            name="email" 
            [(ngModel)]="request.email" 
            required
            class="form-control">
        </div>

        <div class="form-group">
          <label for="country">Country (2-letter code) *</label>
          <input 
            type="text" 
            id="country" 
            name="country" 
            [(ngModel)]="request.country" 
            required
            maxlength="2"
            class="form-control">
        </div>

        <div class="form-group">
          <label for="notBefore">Valid From</label>
          <input 
            type="datetime-local" 
            id="notBefore" 
            name="notBefore" 
            [(ngModel)]="request.notBefore" 
            class="form-control">
        </div>

        <div class="form-group">
          <label for="notAfter">Valid To</label>
          <input 
            type="datetime-local" 
            id="notAfter" 
            name="notAfter" 
            [(ngModel)]="request.notAfter" 
            class="form-control">
        </div>

        <div class="form-actions">
          <button 
            type="submit" 
            [disabled]="!certificateForm.form.valid || loading"
            class="btn btn-primary">
            {{ loading ? 'Issuing...' : 'Issue Certificate' }}
          </button>
          <button 
            type="button" 
            (click)="resetForm()"
            class="btn btn-secondary">
            Reset
          </button>
        </div>
      </form>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="success" class="success">
        Certificate issued successfully!
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 800px;
      margin: 0 auto;
    }

    .form-group {
      margin-bottom: 20px;
    }

    label {
      display: block;
      margin-bottom: 5px;
      font-weight: 600;
    }

    .form-control {
      width: 100%;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }

    .form-control:focus {
      outline: none;
      border-color: #007bff;
      box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
    }

    .form-actions {
      margin-top: 30px;
      display: flex;
      gap: 10px;
    }

    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }

    .btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .btn-primary {
      background-color: #007bff;
      color: white;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .error {
      color: #dc3545;
      background-color: #f8d7da;
      border: 1px solid #f5c6cb;
      padding: 10px;
      border-radius: 4px;
      margin-top: 20px;
    }

    .success {
      color: #155724;
      background-color: #d4edda;
      border: 1px solid #c3e6cb;
      padding: 10px;
      border-radius: 4px;
      margin-top: 20px;
    }
  `]
})
export class IssueCertificateComponent implements OnInit {
  request: IssueCertificateRequest = {
    signingCertificate: '',
    commonName: '',
    organization: '',
    organizationalUnit: '',
    email: '',
    country: '',
    notBefore: '',
    notAfter: '',
    keyUsage: [],
    extendedKeyUsage: [],
    subjectAlternativeNames: [],
    issuerAlternativeNames: [],
    nameConstraints: '',
    basicConstraints: '',
    certificatePolicy: ''
  };

  signingCertificates: Certificate[] = [];
  loading = false;
  error: string | null = null;
  success = false;

  constructor(private certificatesService: CertificatesService) {}

  ngOnInit(): void {
    this.loadSigningCertificates();
  }

  loadSigningCertificates(): void {
    this.certificatesService.getAllValidSigningCertificates().subscribe({
      next: (certs) => {
        this.signingCertificates = certs;
      },
      error: (err) => {
        console.error('Error loading signing certificates:', err);
        this.error = 'Failed to load signing certificates';
      }
    });
  }

  onSubmit(): void {
    if (!this.request.signingCertificate || !this.request.commonName || 
        !this.request.organization || !this.request.organizationalUnit || 
        !this.request.email || !this.request.country) {
      this.error = 'Please fill in all required fields';
      return;
    }

    this.loading = true;
    this.error = null;
    this.success = false;

    this.certificatesService.issueCertificate(this.request).subscribe({
      next: () => {
        this.loading = false;
        this.success = true;
        this.resetForm();
      },
      error: (err) => {
        this.loading = false;
        this.error = 'Failed to issue certificate';
        console.error('Error issuing certificate:', err);
      }
    });
  }

  resetForm(): void {
    this.request = {
      signingCertificate: '',
      commonName: '',
      organization: '',
      organizationalUnit: '',
      email: '',
      country: '',
      notBefore: '',
      notAfter: '',
      keyUsage: [],
      extendedKeyUsage: [],
      subjectAlternativeNames: [],
      issuerAlternativeNames: [],
      nameConstraints: '',
      basicConstraints: '',
      certificatePolicy: ''
    };
    this.success = false;
    this.error = null;
  }
}
