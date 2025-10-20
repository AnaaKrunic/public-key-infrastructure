import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { combineLatest } from 'rxjs';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { AuthService } from '../../../services/auth/auth.service';
import { TemplateService } from '../../../services/template/template.service';
import { Certificate } from '../../../models/Certificate';
import { IssueCertificateRequest } from '../../../models/IssueCertificateRequest';
import { CertificateType } from '../../../models/CertificateType';
import { Role } from '../../../models/Role';
import { KeyUsageValue } from '../../../models/KeyUsageValue';
import { ExtendedKeyUsageValue } from '../../../models/ExtendedKeyUsageValue';
import { Template } from '../../../models/Template';

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
            (change)="onSigningCertificateChange()"
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

        <!-- Template Selection Section -->
        <div class="form-group" *ngIf="availableTemplates.length > 0 && selectedCertificateType !== 'ROOT'">
          <label for="templateSelect">Template (Optional)</label>
          <select 
            id="templateSelect" 
            name="templateSelect" 
            [(ngModel)]="selectedTemplateId" 
            (change)="onTemplateChange()"
            class="form-control">
            <option value="">No template - manual configuration</option>
            <option *ngFor="let template of availableTemplates" [value]="template.id">
              {{ template.name }}
            </option>
          </select>
          <small class="form-text">
            <strong>Note:</strong> Selecting a template will pre-fill extensions and validation rules. You can still add additional extensions below.
          </small>
        </div>

        <!-- Template Preview -->
        <div *ngIf="selectedTemplate" class="template-preview">
          <h4>Selected Template: {{ selectedTemplate.name }}</h4>
          <div class="info-box">
            <strong>ℹ️ Note:</strong> This template provides default extensions and validation rules. 
            You can add additional extensions below (in the "Certificate Extensions" section), 
            as long as the total set doesn't violate the signing certificate's policy.
          </div>
          <div class="template-info">
            <div class="template-detail">
              <strong>CA Issuer:</strong>
              <code>{{ selectedTemplate.caIssuerSerialNumber }}</code>
            </div>
            <div class="template-detail">
              <strong>CN Pattern:</strong>
              <code>{{ selectedTemplate.cnRegex }}</code>
            </div>
            <div class="template-detail">
              <strong>SAN Pattern:</strong>
              <code>{{ selectedTemplate.sanRegex }}</code>
            </div>
            <div class="template-detail">
              <strong>Max Validity:</strong>
              <code>{{ selectedTemplate.ttl }} days</code>
            </div>
            <div class="template-detail">
              <strong>Key Usage:</strong>
              <code>{{ selectedTemplate.keyUsage }}</code>
            </div>
            <div class="template-detail">
              <strong>Extended Key Usage:</strong>
              <code>{{ selectedTemplate.extendedKeyUsage }}</code>
            </div>
          </div>
        </div>

        <!-- Certificate Extensions Section -->
        <div class="extensions-section" *ngIf="extensions.length > 0">
          <h3>Certificate Extensions</h3>
          <div class="extension-item" *ngFor="let ext of extensions; let i = index">
            <div class="form-group" style="flex: 1;">
              <label>Extension Type</label>
              <select [(ngModel)]="ext.key" name="extKey{{i}}" (change)="clearExtensionValue(ext)" class="form-control">
                <option value="">Select extension</option>
                <option *ngFor="let key of getAvailableKeys(ext)" [value]="key.value">
                  {{ key.label }}
                </option>
              </select>
            </div>
            
            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'keyUsage'">
              <label>Key Usage Values</label>
              <select [(ngModel)]="ext.value" name="extValue{{i}}" multiple class="form-control" size="5">
                <option *ngFor="let usage of keyUsageOptions" [value]="usage.value">
                  {{ usage.label }}
                </option>
              </select>
            </div>
            
            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'extendedKeyUsage'">
              <label>Extended Key Usage Values</label>
              <select [(ngModel)]="ext.value" name="extValue{{i}}" multiple class="form-control" size="5">
                <option *ngFor="let usage of extendedKeyUsageOptions" [value]="usage.value">
                  {{ usage.label }}
                </option>
              </select>
            </div>

            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'subjectAlternativeNames'">
              <label>Subject Alternative Names</label>
              <div class="chip-container">
                <div class="chip" *ngFor="let san of ext.value">
                  {{ san }}
                  <button type="button" (click)="removeSan(ext, san)" class="chip-remove">×</button>
                </div>
              </div>
              <input 
                type="text" 
                placeholder="Add SAN (press Enter)" 
                (keyup.enter)="addSan(ext, $event)" 
                class="form-control">
            </div>

            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'issuerAlternativeNames'">
              <label>Issuer Alternative Names</label>
              <div class="chip-container">
                <div class="chip" *ngFor="let ian of ext.value">
                  {{ ian }}
                  <button type="button" (click)="removeSan(ext, ian)" class="chip-remove">×</button>
                </div>
              </div>
              <input 
                type="text" 
                placeholder="Add IAN (press Enter)" 
                (keyup.enter)="addSan(ext, $event)" 
                class="form-control">
            </div>

            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'nameConstraints'">
              <label>Name Constraints</label>
              <input 
                type="text" 
                [(ngModel)]="ext.value" 
                name="extValue{{i}}" 
                placeholder="e.g., .example.com"
                class="form-control">
              <small class="form-hint">Specify permitted/excluded subtrees</small>
            </div>

            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'basicConstraints'">
              <label>Basic Constraints</label>
              <div style="display: flex; gap: 10px;">
                <div style="flex: 1;">
                  <label style="font-size: 12px;">Is CA</label>
                  <select [(ngModel)]="ext.value.isCa" name="extValueIsCa{{i}}" class="form-control">
                    <option [value]="true">Yes</option>
                    <option [value]="false">No</option>
                  </select>
                </div>
                <div style="flex: 1;">
                  <label style="font-size: 12px;">Path Length</label>
                  <input 
                    type="number" 
                    [(ngModel)]="ext.value.pathLen" 
                    name="extValuePathLen{{i}}" 
                    placeholder="Path length"
                    min="0"
                    class="form-control">
                </div>
              </div>
            </div>

            <div class="form-group" style="flex: 2;" *ngIf="ext.key === 'certificatePolicy'">
              <label>Certificate Policy</label>
              <input 
                type="text" 
                [(ngModel)]="ext.value.policyIdentifier" 
                name="extValuePolicyId{{i}}" 
                placeholder="Policy Identifier (OID)"
                class="form-control">
              <input 
                type="text" 
                [(ngModel)]="ext.value.cpsUri" 
                name="extValueCpsUri{{i}}" 
                placeholder="CPS URI (optional)"
                class="form-control"
                style="margin-top: 5px;">
              <input 
                type="text" 
                [(ngModel)]="ext.value.userNotice" 
                name="extValueUserNotice{{i}}" 
                placeholder="User Notice (optional)"
                class="form-control"
                style="margin-top: 5px;">
            </div>
            
            <button type="button" (click)="removeExtension(i)" class="btn btn-danger btn-sm" style="align-self: flex-end;">
              Remove
            </button>
          </div>
        </div>

        <div class="form-actions">
          <button type="button" (click)="addExtension()" class="btn btn-secondary">
            Add Extension
          </button>
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

    .extensions-section {
      margin: 30px 0;
      padding: 20px;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      background: #f9f9f9;
    }

    .extensions-section h3 {
      margin: 0 0 20px 0;
      color: #333;
      font-size: 18px;
      font-weight: 600;
    }

    .extension-item {
      display: flex;
      gap: 15px;
      margin-bottom: 20px;
      align-items: flex-start;
    }

    .extension-item .form-group {
      margin-bottom: 0;
    }

    .chip-container {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
      min-height: 30px;
    }

    .chip {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px 8px;
      background: #e9ecef;
      border-radius: 16px;
      font-size: 12px;
    }

    .chip-remove {
      background: none;
      border: none;
      color: #dc3545;
      cursor: pointer;
      font-size: 16px;
      padding: 0;
      font-weight: bold;
    }

    .form-hint {
      display: block;
      font-size: 11px;
      color: #6c757d;
      margin-top: 3px;
    }

    .btn-sm {
      padding: 5px 10px;
      font-size: 12px;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .btn-danger:hover:not(:disabled) {
      background-color: #c82333;
    }

    .template-preview {
      margin: 20px 0;
      padding: 20px;
      background-color: #f8f9fa;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
    }

    .template-preview h4 {
      margin: 0 0 15px 0;
      color: #495057;
      font-size: 16px;
    }

    .template-info {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 10px;
    }

    .template-detail {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }

    .template-detail strong {
      color: #495057;
      font-size: 13px;
    }

    .template-detail code {
      background-color: #e9ecef;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      word-break: break-all;
    }

    .info-box {
      background-color: #e7f3ff;
      border-left: 4px solid #2196F3;
      padding: 12px 15px;
      margin-bottom: 15px;
      border-radius: 4px;
      font-size: 13px;
      line-height: 1.5;
    }

    .info-box strong {
      color: #1976D2;
      display: block;
      margin-bottom: 5px;
    }
  `]
})
export class IssueCertificateComponent implements OnInit {
  private certificatesService = inject(CertificatesService);
  private authService = inject(AuthService);
  private templateService = inject(TemplateService);

  selectedCertificateType: string = '';
  currentUserRole: string | null = null;
  
  // Template-related properties
  availableTemplates: Template[] = [];
  selectedTemplate: Template | null = null;
  selectedTemplateId: string = '';
  
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
    certificatePolicy: '',
    templateId: null
  };

  signingCertificates: Certificate[] = [];
  loading = false;
  error: string | null = null;
  success = false;

  // Extension management
  extensions: any[] = [];
  
  keyUsageOptions = [
    { value: KeyUsageValue.DigitalSignature, label: 'Digital Signature' },
    { value: KeyUsageValue.NonRepudiation, label: 'Non Repudiation' },
    { value: KeyUsageValue.KeyEncipherment, label: 'Key Encipherment' },
    { value: KeyUsageValue.DataEncipherment, label: 'Data Encipherment' },
    { value: KeyUsageValue.KeyAgreement, label: 'Key Agreement' },
    { value: KeyUsageValue.CertificateSigning, label: 'Certificate Signing' },
    { value: KeyUsageValue.CrlSigning, label: 'CRL Signing' },
    { value: KeyUsageValue.EncipherOnly, label: 'Encipher Only' },
    { value: KeyUsageValue.DecipherOnly, label: 'Decipher Only' }
  ];
  
  extendedKeyUsageOptions = [
    { value: ExtendedKeyUsageValue.ServerAuthentication, label: 'Server Authentication' },
    { value: ExtendedKeyUsageValue.ClientAuthentication, label: 'Client Authentication' },
    { value: ExtendedKeyUsageValue.CodeSigning, label: 'Code Signing' },
    { value: ExtendedKeyUsageValue.EmailProtection, label: 'Email Protection' },
    { value: ExtendedKeyUsageValue.TimeStamping, label: 'Time Stamping' },
    { value: ExtendedKeyUsageValue.OcspSigning, label: 'OCSP Signing' }
  ];

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
      this.clearTemplateSelection();
    }
  }

  onSigningCertificateChange(): void {
    // Load templates for selected signing certificate
    if (this.request.signingCertificate) {
      this.loadTemplatesForCA(this.request.signingCertificate);
    } else {
      this.clearTemplateSelection();
    }
  }

  onTemplateChange(): void {
    if (this.selectedTemplateId) {
      this.selectedTemplate = this.availableTemplates.find(t => t.id.toString() === this.selectedTemplateId) || null;
      if (this.selectedTemplate) {
        this.applyTemplateToRequest();
      }
    } else {
      this.clearTemplateSelection();
    }
  }

  loadTemplatesForCA(caSerialNumber: string): void {
    this.templateService.getTemplatesForCA(caSerialNumber).subscribe({
      next: (templates) => {
        this.availableTemplates = templates;
      },
      error: (error) => {
        console.error('Error loading templates:', error);
        this.availableTemplates = [];
      }
    });
  }

  applyTemplateToRequest(): void {
    if (!this.selectedTemplate) return;

    // Apply template's default extensions to the request
    if (this.selectedTemplate.keyUsage) {
      const templateKeyUsage = this.selectedTemplate.keyUsage.split(',').map(s => s.trim());
      // Merge with existing key usage, avoiding duplicates
      this.request.keyUsage = [...new Set([...this.request.keyUsage, ...templateKeyUsage])];
    }

    if (this.selectedTemplate.extendedKeyUsage) {
      const templateExtendedKeyUsage = this.selectedTemplate.extendedKeyUsage.split(',').map(s => s.trim());
      // Merge with existing extended key usage, avoiding duplicates
      this.request.extendedKeyUsage = [...new Set([...this.request.extendedKeyUsage, ...templateExtendedKeyUsage])];
    }

    // Set template ID in request
    this.request.templateId = this.selectedTemplate.id;
  }

  clearTemplateSelection(): void {
    this.selectedTemplate = null;
    this.selectedTemplateId = '';
    this.availableTemplates = [];
    this.request.templateId = null;
  }

  validateExtensionsAgainstPolicy(): boolean {
    if (!this.selectedTemplate) {
      return true; // No template, no additional validation needed
    }

    // Get final extensions (template + user extensions)
    const finalKeyUsage = [...new Set([...this.getTemplateKeyUsage(), ...(this.request.keyUsage || [])])];
    const finalExtendedKeyUsage = [...new Set([...this.getTemplateExtendedKeyUsage(), ...(this.request.extendedKeyUsage || [])])];

    // Validate that end-entity certificates don't have CA-specific key usage
    if (this.selectedCertificateType === 'END_ENTITY') {
      const forbiddenKeyUsage = ['keyCertSign', 'cRLSign'];
      for (const usage of forbiddenKeyUsage) {
        if (finalKeyUsage.includes(usage)) {
          this.error = `End-entity certificates cannot have ${usage} key usage`;
          return false;
        }
      }
    }

    return true;
  }

  private getTemplateKeyUsage(): string[] {
    if (!this.selectedTemplate || !this.selectedTemplate.keyUsage) {
      return [];
    }
    return this.selectedTemplate.keyUsage.split(',').map(s => s.trim());
  }

  private getTemplateExtendedKeyUsage(): string[] {
    if (!this.selectedTemplate || !this.selectedTemplate.extendedKeyUsage) {
      return [];
    }
    return this.selectedTemplate.extendedKeyUsage.split(',').map(s => s.trim());
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

    // Validate extensions against policy
    if (!this.validateExtensionsAgainstPolicy()) {
      return;
    }

    this.loading = true;
    this.error = null;
    this.success = false;

    // Populate request with extension values
    this.request.keyUsage = this.getKeyUsageValues();
    this.request.extendedKeyUsage = this.getExtendedKeyUsageValues();
    this.request.subjectAlternativeNames = this.getSubjectAlternativeNames();
    this.request.issuerAlternativeNames = this.getIssuerAlternativeNames();
    this.request.nameConstraints = this.getNameConstraints();
    this.request.basicConstraints = this.getBasicConstraints();
    this.request.certificatePolicy = this.getCertificatePolicy();

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

  // Extension management methods
  addExtension() {
    this.extensions.push({
      key: '',
      value: []
    });
  }

  removeExtension(index: number) {
    this.extensions.splice(index, 1);
  }

  getAvailableKeys(ext: any) {
    const usedKeys = this.extensions.map(e => e.key).filter(k => k !== ext.key);
    return [
      { value: 'keyUsage', label: 'Key Usage' },
      { value: 'extendedKeyUsage', label: 'Extended Key Usage' },
      { value: 'subjectAlternativeNames', label: 'Subject Alternative Names' },
      { value: 'issuerAlternativeNames', label: 'Issuer Alternative Names' },
      { value: 'nameConstraints', label: 'Name Constraints' },
      { value: 'basicConstraints', label: 'Basic Constraints' },
      { value: 'certificatePolicy', label: 'Certificate Policy' }
    ].filter(key => !usedKeys.includes(key.value));
  }

  clearExtensionValue(ext: any) {
    if (ext.key === 'basicConstraints') {
      ext.value = { isCa: false, pathLen: null };
    } else if (ext.key === 'certificatePolicy') {
      ext.value = { policyIdentifier: '', cpsUri: '', userNotice: '' };
    } else if (ext.key === 'nameConstraints') {
      ext.value = '';
    } else {
      ext.value = [];
    }
  }

  addSan(ext: any, event: any) {
    const value = event.target.value.trim();
    if (value && !ext.value.includes(value)) {
      ext.value.push(value);
      event.target.value = '';
    }
  }

  removeSan(ext: any, san: string) {
    const index = ext.value.indexOf(san);
    if (index > -1) {
      ext.value.splice(index, 1);
    }
  }

  // Helper methods to get extension values
  getKeyUsageValues(): string[] {
    const keyUsageExt = this.extensions.find(ext => ext.key === 'keyUsage');
    return keyUsageExt ? keyUsageExt.value : [];
  }

  getExtendedKeyUsageValues(): string[] {
    const extKeyUsageExt = this.extensions.find(ext => ext.key === 'extendedKeyUsage');
    return extKeyUsageExt ? extKeyUsageExt.value : [];
  }

  getSubjectAlternativeNames(): string[] {
    const sanExt = this.extensions.find(ext => ext.key === 'subjectAlternativeNames');
    return sanExt ? sanExt.value : [];
  }

  getIssuerAlternativeNames(): string[] {
    const ianExt = this.extensions.find(ext => ext.key === 'issuerAlternativeNames');
    return ianExt ? ianExt.value : [];
  }

  getNameConstraints(): string {
    const ncExt = this.extensions.find(ext => ext.key === 'nameConstraints');
    return ncExt ? ncExt.value : '';
  }

  getBasicConstraints(): string {
    const bcExt = this.extensions.find(ext => ext.key === 'basicConstraints');
    if (bcExt && bcExt.value) {
      return JSON.stringify({ isCa: bcExt.value.isCa, pathLen: bcExt.value.pathLen });
    }
    return '';
  }

  getCertificatePolicy(): string {
    const cpExt = this.extensions.find(ext => ext.key === 'certificatePolicy');
    if (cpExt && cpExt.value) {
      return JSON.stringify(cpExt.value);
    }
    return '';
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
    this.extensions = [];
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
