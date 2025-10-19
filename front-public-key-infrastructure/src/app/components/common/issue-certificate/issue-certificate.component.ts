import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { combineLatest } from 'rxjs';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { AuthService } from '../../../services/auth/auth.service';
import { Certificate } from '../../../models/Certificate';
import { IssueCertificateRequest } from '../../../models/IssueCertificateRequest';
import { CertificateType } from '../../../models/CertificateType';
import { Role } from '../../../models/Role';

@Component({
  selector: 'app-issue-certificate',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h1>Issue Certificate</h1>
      
      <!-- Certificate Type Selection -->
      <div class="form-group">
        <label for="certificateType">Certificate Type *</label>
        <select 
          id="certificateType" 
          name="certificateType" 
          [(ngModel)]="selectedCertificateType" 
          (change)="onCertificateTypeChange()"
          required
          class="form-control">
          <option value="">Select certificate type</option>
          <option value="ROOT" *ngIf="currentUserRole === 'ADMIN'">Root CA (Self-signed)</option>
          <option value="INTERMEDIATE">Intermediate CA</option>
          <option value="END_ENTITY">End Entity Certificate</option>
        </select>
        <small class="form-text" *ngIf="currentUserRole === 'ADMIN'">
          <strong>Root CA:</strong> Self-signed certificate (no signing certificate needed)<br>
          <strong>Intermediate CA:</strong> Signed by Root CA or another Intermediate CA<br>
          <strong>End Entity:</strong> Signed by Root CA or Intermediate CA
        </small>
        <small class="form-text" *ngIf="currentUserRole === 'CA_USER'">
          <strong>Intermediate CA:</strong> Signed by Root CA or another Intermediate CA from your organization<br>
          <strong>End Entity:</strong> Signed by Root CA or Intermediate CA from your organization
        </small>
      </div>
      
      <form (ngSubmit)="onSubmit()" #certificateForm="ngForm">
        <!-- Signing Certificate (not required for Root CA) -->
        <div class="form-group" *ngIf="selectedCertificateType !== 'ROOT'">
          <label for="signingCertificate">Signing Certificate *</label>
          <select 
            id="signingCertificate" 
            name="signingCertificate" 
            [(ngModel)]="request.signingCertificate" 
            [required]="selectedCertificateType !== 'ROOT'"
            class="form-control">
            <option value="">Select a signing certificate</option>
            <option *ngFor="let cert of signingCertificates" [value]="cert.serialNumber">
              {{ cert.subjectCN }} ({{ cert.serialNumber }})
            </option>
          </select>
          <small class="form-text" *ngIf="currentUserRole === 'CA_USER'">
            <strong>Note:</strong> You can only use certificates from your organization.
          </small>
          <small class="form-text" *ngIf="currentUserRole === 'ADMIN'">
            <strong>Note:</strong> You can use certificates from all organizations.
          </small>
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
            [readonly]="currentUserRole === 'CA_USER'"
            class="form-control">
          <small class="form-text" *ngIf="currentUserRole === 'CA_USER'">
            <strong>Note:</strong> CA users can only issue certificates for their own organization.
          </small>
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

    .form-control[readonly] {
      background-color: #f8f9fa;
      color: #6c757d;
      cursor: not-allowed;
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

    .form-text {
      color: #6c757d;
      font-size: 12px;
      margin-top: 5px;
      line-height: 1.4;
    }
  `]
})
export class IssueCertificateComponent implements OnInit {
  private certificatesService = inject(CertificatesService);
  private authService = inject(AuthService);

  selectedCertificateType: string = '';
  currentUserRole: string | null = null;
  
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

  ngOnInit(): void {
    // Combine role and user observables to ensure both are available
    combineLatest([
      this.authService.role$,
      this.authService.user$
    ]).subscribe(([role, user]) => {
      console.log('IssueCertificate ngOnInit - Role:', role, 'User:', user);
      this.currentUserRole = role;
      
      // If CA user, clear any selected Root CA type
      if (role === 'CA_USER' && this.selectedCertificateType === 'ROOT') {
        this.selectedCertificateType = '';
      }
      
      // Pre-fill organization for CA users
      if (user && role === 'CA_USER' && user.organization) {
        this.request.organization = user.organization;
        console.log('Pre-filled organization for CA user:', user.organization);
        console.log('Request object after pre-fill:', this.request);
      } else {
        console.log('Not pre-filling organization. User:', user, 'Role:', role, 'User org:', user?.organization);
      }
    });

    // Also try to get current user directly as a fallback
    this.authService.getCurrentUser().subscribe(user => {
      console.log('Direct getCurrentUser call - User:', user);
      if (user && user.role === 'CA_USER' && user.organization) {
        this.request.organization = user.organization;
        console.log('Fallback pre-fill organization:', user.organization);
      }
    });
    
    this.loadSigningCertificates();
  }

  onCertificateTypeChange(): void {
    // Clear signing certificate when switching to Root CA
    if (this.selectedCertificateType === 'ROOT') {
      this.request.signingCertificate = '';
    }
  }

  loadSigningCertificates(): void {
    // Load appropriate certificates based on user role
    if (this.currentUserRole === 'CA_USER') {
      // CA users can only use certificates from their organization
      this.certificatesService.getOrganizationSigningCertificates().subscribe({
        next: (certs) => {
          this.signingCertificates = certs.filter(cert => cert.canSign);
        },
        error: (err) => {
          console.error('Error loading organization signing certificates:', err);
          this.error = 'Failed to load your organization\'s signing certificates';
        }
      });
    } else {
      // Admins can use all valid signing certificates
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
  }

  onSubmit(): void {
    // Validation based on certificate type
    if (!this.selectedCertificateType) {
      this.error = 'Please select a certificate type';
      return;
    }

    // CA users cannot issue Root CA certificates
    if (this.currentUserRole === 'CA_USER' && this.selectedCertificateType === 'ROOT') {
      this.error = 'CA users cannot issue Root CA certificates. Only administrators can create Root CA certificates.';
      return;
    }

    if (this.selectedCertificateType !== 'ROOT' && !this.request.signingCertificate) {
      this.error = 'Please select a signing certificate';
      return;
    }

    if (!this.request.commonName || !this.request.organization || 
        !this.request.organizationalUnit || !this.request.email || !this.request.country) {
      this.error = 'Please fill in all required fields';
      return;
    }

    this.loading = true;
    this.error = null;
    this.success = false;

    // Map form data to appropriate DTO based on certificate type
    let certificateRequest;
    
    if (this.selectedCertificateType === 'ROOT') {
      // For Root CA, use CreateRootCertificateDTO format
      const rootRequest = {
        subjectCN: this.request.commonName,
        subjectO: this.request.organization,
        subjectOU: this.request.organizationalUnit,
        subjectL: '', // Add if you have locality field
        subjectST: '', // Add if you have state field
        subjectC: this.request.country,
        subjectE: this.request.email,
        validityDays: this.calculateValidityDays(),
        keySize: 2048, // Default key size
        keyUsage: ['keyCertSign', 'cRLSign'], // Root CA key usage
        basicConstraints: {
          ca: true,
          pathLength: null // Root CA has no path length constraint
        }
      };
      certificateRequest = this.certificatesService.createRootCertificate(rootRequest);
    } else if (this.selectedCertificateType === 'INTERMEDIATE') {
      // For Intermediate CA, use CreateIntermediateCertificateDTO format
      const intermediateRequest = {
        issuerCertificateId: this.getCertificateIdFromSerial(this.request.signingCertificate),
        subjectCN: this.request.commonName,
        subjectO: this.request.organization,
        subjectOU: this.request.organizationalUnit,
        subjectL: '',
        subjectST: '',
        subjectC: this.request.country,
        subjectE: this.request.email,
        validityDays: this.calculateValidityDays(),
        keySize: 2048,
        keyUsage: ['keyCertSign', 'cRLSign'],
        basicConstraints: {
          ca: true,
          pathLength: null // Intermediate CA has unlimited path length (no constraints)
        }
      };
      certificateRequest = this.certificatesService.createIntermediateCertificate(intermediateRequest);
    } else if (this.selectedCertificateType === 'END_ENTITY') {
      // For End Entity, use CreateEndEntityCertificateDTO format
      const endEntityRequest = {
        issuerCertificateId: this.getCertificateIdFromSerial(this.request.signingCertificate),
        subjectCN: this.request.commonName,
        subjectO: this.request.organization,
        subjectOU: this.request.organizationalUnit,
        subjectL: '',
        subjectST: '',
        subjectC: this.request.country,
        subjectE: this.request.email,
        validityDays: this.calculateValidityDays(),
        keySize: 2048,
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth', 'clientAuth'],
        subjectAlternativeNames: []
      };
      certificateRequest = this.certificatesService.createEndEntityCertificate(endEntityRequest);
    } else {
      // Fallback to regular issue certificate
      certificateRequest = this.certificatesService.issueCertificate(this.request);
    }

    certificateRequest.subscribe({
      next: () => {
        this.loading = false;
        this.success = true;
        this.resetForm();
      },
      error: (err) => {
        this.loading = false;
        this.error = `Failed to create ${this.selectedCertificateType.toLowerCase()} certificate`;
        console.error('Error creating certificate:', err);
      }
    });
  }

  resetForm(): void {
    this.selectedCertificateType = '';
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

  private calculateValidityDays(): number {
    if (this.request.notBefore && this.request.notAfter) {
      const startDate = new Date(this.request.notBefore);
      const endDate = new Date(this.request.notAfter);
      const diffTime = endDate.getTime() - startDate.getTime();
      return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }
    // Default validity based on certificate type
    switch (this.selectedCertificateType) {
      case 'ROOT':
        return 3650; // 10 years for Root CA
      case 'INTERMEDIATE':
        return 1825; // 5 years for Intermediate CA
      case 'END_ENTITY':
        return 365; // 1 year for End Entity
      default:
        return 365;
    }
  }

  private getCertificateIdFromSerial(serialNumber: string): number {
    // Find the certificate by serial number and return its ID
    const cert = this.signingCertificates.find(c => c.serialNumber === serialNumber);
    console.log('DEBUG: Looking for certificate with serial:', serialNumber);
    console.log('DEBUG: Available certificates:', this.signingCertificates.map(c => ({ id: c.id, serial: c.serialNumber })));
    console.log('DEBUG: Found certificate:', cert);
    return cert ? cert.id : 0;
  }
}
