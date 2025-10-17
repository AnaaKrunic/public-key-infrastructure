import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { CertificateRequestsService } from '../../../services/certificates/certificate-requests.service';
import { CreateCertificateRequest } from '../../../models/CreateCertificateRequest';
import { KeyPair } from '../../../models/KeyPair';

@Component({
  selector: 'app-request-certificate',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h1>Request Certificate</h1>
      
      <form (ngSubmit)="onSubmit()" #requestForm="ngForm">
        <div class="form-group">
          <label for="signingOrganization">Signing Organization *</label>
          <input 
            type="text" 
            id="signingOrganization" 
            name="signingOrganization" 
            [(ngModel)]="request.signingOrganization" 
            required
            class="form-control">
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
            [disabled]="!requestForm.form.valid || loading"
            class="btn btn-primary">
            {{ loading ? 'Creating...' : 'Create Certificate Request' }}
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

      <div *ngIf="success && keyPair" class="success">
        <h3>Certificate Request Created Successfully!</h3>
        <p>Your key pair has been generated. Please save your private key securely:</p>
        <div class="key-pair">
          <h4>Private Key:</h4>
          <textarea readonly class="key-text">{{ keyPair.privateKey }}</textarea>
          <h4>Public Key:</h4>
          <textarea readonly class="key-text">{{ keyPair.publicKey }}</textarea>
        </div>
        <button (click)="downloadKeys()" class="btn btn-primary">Download Keys</button>
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
      padding: 20px;
      border-radius: 4px;
      margin-top: 20px;
    }

    .key-pair {
      margin-top: 20px;
    }

    .key-text {
      width: 100%;
      height: 100px;
      font-family: monospace;
      font-size: 12px;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 10px;
      margin-bottom: 10px;
    }
  `]
})
export class RequestCertificateComponent implements OnInit {
  request: CreateCertificateRequest = {
    signingOrganization: '',
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

  keyPair: KeyPair | null = null;
  loading = false;
  error: string | null = null;
  success = false;

  constructor(private certificateRequestsService: CertificateRequestsService) {}

  ngOnInit(): void {
    // Component initialization
  }

  onSubmit(): void {
    if (!this.request.signingOrganization || !this.request.commonName || 
        !this.request.organization || !this.request.organizationalUnit || 
        !this.request.email || !this.request.country) {
      this.error = 'Please fill in all required fields';
      return;
    }

    this.loading = true;
    this.error = null;
    this.success = false;
    this.keyPair = null;

    this.certificateRequestsService.createCertificateRequest(this.request).subscribe({
      next: (keyPair) => {
        this.loading = false;
        this.success = true;
        this.keyPair = keyPair;
      },
      error: (err) => {
        this.loading = false;
        this.error = 'Failed to create certificate request';
        console.error('Error creating certificate request:', err);
      }
    });
  }

  resetForm(): void {
    this.request = {
      signingOrganization: '',
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
    this.keyPair = null;
  }

  downloadKeys(): void {
    if (!this.keyPair) return;

    const content = `Private Key:\n${this.keyPair.privateKey}\n\nPublic Key:\n${this.keyPair.publicKey}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'certificate_keys.txt';
    link.click();
    window.URL.revokeObjectURL(url);
  }
}
