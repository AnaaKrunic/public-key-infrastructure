import { Component, OnInit, ViewChild, inject } from '@angular/core';
import { CommonModule, DatePipe, NgFor, NgIf } from '@angular/common';
import { FormsModule, NgForm, NgModel } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatNativeDateModule } from '@angular/material/core';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatTabGroup, MatTab, MatTabContent } from '@angular/material/tabs';
import { MatChipRemove, MatChipRow, MatChipSet } from '@angular/material/chips';
import { MatDialog } from '@angular/material/dialog';
import { ToastrService } from 'ngx-toastr';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { CertificateRequestsService } from '../../../services/certificates/certificate-requests.service';
import { AuthService } from '../../../services/auth/auth.service';
import { CaUser } from '../../../models/CaUser';
import { CertificateRequest } from '../../../models/CertificateRequest';
import { CreateCertificateRequest } from '../../../models/CreateCertificateRequest';
import { KeyUsageValue } from '../../../models/KeyUsageValue';
import { ExtendedKeyUsageValue } from '../../../models/ExtendedKeyUsageValue';

@Component({
  selector: 'app-request-certificate',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatButtonModule,
    MatDatepickerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatNativeDateModule,
    MatProgressSpinner,
    MatSelectModule,
    MatTabGroup,
    MatTab,
    MatTabContent,
    MatChipRemove,
    MatChipRow,
    MatChipSet,
    DatePipe,
    NgFor,
    NgIf
  ],
  template: `
    <div class="container">
      <h1>Request Certificate</h1>
      
      <div *ngIf="loading" class="loading">
        <mat-spinner></mat-spinner>
      </div>

      <!-- Tab Navigation -->
      <div class="tab-navigation">
        <button 
          class="tab-button" 
          [class.active]="activeTab === 'upload'"
          (click)="activeTab = 'upload'">
          Upload CSR
        </button>
        <button 
          class="tab-button" 
          [class.active]="activeTab === 'generate'"
          (click)="activeTab = 'generate'">
          Generate Request
        </button>
      </div>

      <!-- Upload CSR Tab -->
      <div *ngIf="activeTab === 'upload'" class="tab-content">
        <form #csrForm="ngForm" (ngSubmit)="onSubmitCSR(csrForm)">
          
          <div class="form-group">
            <label for="signingCertificate">Signing Certificate *</label>
            <select 
              id="signingCertificate" 
              name="signingCertificate" 
              [(ngModel)]="selectedCertificateId" 
              (change)="onCertificateChange($event)"
              required
              class="form-control">
              <option value="">Select Signing Certificate</option>
              <option *ngFor="let cert of signingCertificates" [value]="cert.serialNumber">
                {{ cert.commonName }} - {{ cert.organization }} - {{ cert.organizationalUnit }} - {{ cert.serialNumber }}
              </option>
            </select>
          </div>

          <div class="form-group">
            <label>CSR File *</label>
            <div class="file-upload" (click)="csrFileInput.click()" (drop)="onDrop($event, 'csr')" (dragover)="onDragOver($event)" (dragleave)="onDragLeave($event)">
              <div class="upload-content">
                <div class="upload-icon">📁</div>
                <p class="upload-text">Drag 'n' drop CSR here, or click to select the file.</p>
                <p class="upload-hint">Supported: .csr, .pem</p>
                <div *ngIf="csrFileName" class="selected-file">
                  <span>{{ csrFileName }}</span>
                  <button type="button" (click)="removeFile($event, 'csr')" class="remove-file-btn">×</button>
                </div>
              </div>
              <input type="file" #csrFileInput accept=".csr,.pem" hidden (change)="onFileChosen($event, 'csr')" name="csrFile" required>
            </div>
          </div>

          <div class="form-group">
            <label>Private Key File *</label>
            <div class="file-upload" (click)="privateKeyFileInput.click()" (drop)="onDrop($event, 'privateKey')" (dragover)="onDragOver($event)" (dragleave)="onDragLeave($event)">
              <div class="upload-content">
                <div class="upload-icon">🔐</div>
                <p class="upload-text">Drag 'n' drop private key here, or click to select the file.</p>
                <p class="upload-hint">Supported: .pem, .key (PKCS#8 format)</p>
                <div *ngIf="privateKeyFileName" class="selected-file">
                  <span>{{ privateKeyFileName }}</span>
                  <button type="button" (click)="removeFile($event, 'privateKey')" class="remove-file-btn">×</button>
                </div>
              </div>
              <input type="file" #privateKeyFileInput accept=".pem,.key" hidden (change)="onFileChosen($event, 'privateKey')" name="privateKeyFile" required>
            </div>
          </div>

          <div class="form-group">
            <label for="notAfter">Not After</label>
            <input 
              type="datetime-local" 
              id="notAfter" 
              name="notAfter" 
              [(ngModel)]="dateNotAfter" 
              class="form-control">
          </div>
          
          <div class="form-actions">
            <button 
              type="submit" 
              [disabled]="!csrForm.form.valid || !csrFile || !privateKeyFile || loading"
              class="btn btn-primary">
              {{ loading ? 'Requesting...' : 'Request Certificate' }}
            </button>
          </div>
        </form>
      </div>

      <!-- Generate Request Tab -->
      <div *ngIf="activeTab === 'generate'" class="tab-content">
        <form #requestForm="ngForm" (ngSubmit)="onSubmit(requestForm)">
          
          <div class="form-group">
            <label for="signingCertificateGen">Signing Certificate *</label>
            <select 
              id="signingCertificateGen" 
              name="signingCertificate" 
              [(ngModel)]="selectedCertificateId" 
              (change)="onCertificateChange($event)"
              required
              class="form-control">
              <option value="">Select Signing Certificate</option>
              <option *ngFor="let cert of signingCertificates" [value]="cert.serialNumber">
              {{ cert.commonName }} - {{ cert.organization }} - {{ cert.organizationalUnit }} - {{ cert.serialNumber }}              </option>
            </select>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="commonName">Common Name (CN) *</label>
              <input 
                type="text" 
                id="commonName" 
                name="commonName" 
                [(ngModel)]="commonName" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="organization">Organization (O) *</label>
              <input 
                type="text" 
                id="organization" 
                name="organization" 
                [(ngModel)]="organization" 
                required
                class="form-control">
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="organizationalUnit">Organizational Unit (OU) *</label>
              <input 
                type="text" 
                id="organizationalUnit" 
                name="organizationalUnit" 
                [(ngModel)]="organizationalUnit" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="email">Email Address (E) *</label>
              <input 
                type="email" 
                id="email" 
                name="email" 
                [(ngModel)]="email" 
                required
                class="form-control">
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="country">Country (C) *</label>
              <input 
                type="text" 
                id="country" 
                name="country" 
                [(ngModel)]="country" 
                required
                maxlength="2"
                (input)="onCountryInput($event)"
                class="form-control">
            </div>
            <div class="form-group">
              <label for="notBefore">Not Before</label>
              <input 
                type="datetime-local" 
                id="notBefore" 
                name="notBefore" 
                [(ngModel)]="dateNotBefore" 
                class="form-control">
            </div>
          </div>

          <div class="form-group">
            <label for="notAfterGen">Not After</label>
            <input 
              type="datetime-local" 
              id="notAfterGen" 
              name="notAfter" 
              [(ngModel)]="dateNotAfter" 
              class="form-control">
          </div>

          <div class="extensions-section" *ngIf="extensions.length > 0">
            <h3>Certificate Extensions</h3>
            <div class="extension-item" *ngFor="let ext of extensions; let i = index">
              <div class="form-group">
                <label>Extension</label>
                <select [(ngModel)]="ext.key" name="extKey{{i}}" (change)="clearExtensionValue(ext)" class="form-control">
                  <option value="">Select extension</option>
                  <option *ngFor="let key of getAvailableKeys(ext)" [value]="key.value">
                    {{ key.label }}
                  </option>
                </select>
              </div>
              
              <div class="form-group" *ngIf="ext.key === 'keyUsage'">
                <label>Key Usage</label>
                <select [(ngModel)]="ext.value" name="extValue{{i}}" multiple class="form-control">
                  <option *ngFor="let usage of keyUsageOptions" [value]="usage.value">
                    {{ usage.label }}
                  </option>
                </select>
              </div>
              
              <div class="form-group" *ngIf="ext.key === 'extendedKeyUsage'">
                <label>Extended Key Usage</label>
                <select [(ngModel)]="ext.value" name="extValue{{i}}" multiple class="form-control">
                  <option *ngFor="let usage of extendedKeyUsageOptions" [value]="usage.value">
                    {{ usage.label }}
                  </option>
                </select>
              </div>

              <div class="form-group" *ngIf="ext.key === 'subjectAlternativeNames'">
                <label>Subject Alternative Names</label>
                <div class="chip-container">
                  <div class="chip" *ngFor="let san of ext.value; let j = index">
                    {{ san }}
                    <button type="button" (click)="removeSan(ext, san)" class="chip-remove">×</button>
                  </div>
                </div>
                <input 
                  type="text" 
                  placeholder="Add SAN (e.g., example.com)" 
                  (keyup.enter)="addSan(ext, $event)" 
                  class="form-control">
              </div>

              <div class="form-group" *ngIf="ext.key === 'issuerAlternativeNames'">
                <label>Issuer Alternative Names</label>
                <div class="chip-container">
                  <div class="chip" *ngFor="let ian of ext.value; let j = index">
                    {{ ian }}
                    <button type="button" (click)="removeSan(ext, ian)" class="chip-remove">×</button>
                  </div>
                </div>
                <input 
                  type="text" 
                  placeholder="Add IAN (e.g., issuer.example.com)" 
                  (keyup.enter)="addSan(ext, $event)" 
                  class="form-control">
              </div>

              <div class="form-group" *ngIf="ext.key === 'nameConstraints'">
                <label>Name Constraints</label>
                <input 
                  type="text" 
                  [(ngModel)]="ext.value" 
                  name="extValue{{i}}" 
                  placeholder="e.g., .example.com"
                  class="form-control">
                <small class="form-hint">Specify permitted/excluded subtrees</small>
              </div>

              <div class="form-group" *ngIf="ext.key === 'basicConstraints'">
                <label>Basic Constraints</label>
                <div class="form-row">
                  <div class="form-group">
                    <label>Is CA</label>
                    <select [(ngModel)]="ext.value.isCa" name="extValueIsCa{{i}}" class="form-control">
                      <option [value]="true">Yes</option>
                      <option [value]="false">No</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Path Length</label>
                    <input 
                      type="number" 
                      [(ngModel)]="ext.value.pathLen" 
                      name="extValuePathLen{{i}}" 
                      placeholder="Path length constraint"
                      min="0"
                      class="form-control">
                  </div>
                </div>
              </div>

              <div class="form-group" *ngIf="ext.key === 'certificatePolicy'">
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
                  style="margin-top: 10px;">
                <input 
                  type="text" 
                  [(ngModel)]="ext.value.userNotice" 
                  name="extValueUserNotice{{i}}" 
                  placeholder="User Notice (optional)"
                  class="form-control"
                  style="margin-top: 10px;">
              </div>
              
              <button type="button" (click)="removeExtension(i)" class="btn btn-sm btn-danger remove-btn">
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
              [disabled]="!requestForm.form.valid || loading"
              class="btn btn-primary">
              {{ loading ? 'Generating...' : 'Generate Request' }}
            </button>
          </div>
        </form>
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="success" class="success">
        {{ success }}
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 800px;
      margin: 0 auto;
    }

    h1 {
      margin-bottom: 30px;
      color: #333;
    }

    .loading {
      text-align: center;
      padding: 20px;
    }

    .tab-navigation {
      display: flex;
      margin-bottom: 30px;
      border-bottom: 1px solid #ddd;
    }

    .tab-button {
      padding: 12px 24px;
      border: none;
      background: none;
      cursor: pointer;
      font-size: 16px;
      color: #666;
      border-bottom: 2px solid transparent;
      transition: all 0.3s ease;
    }

    .tab-button:hover {
      color: #007bff;
    }

    .tab-button.active {
      color: #007bff;
      border-bottom-color: #007bff;
    }

    .tab-content {
      margin-top: 20px;
    }

    .form-group {
      margin-bottom: 20px;
    }

    .form-row {
      display: flex;
      gap: 20px;
    }

    .form-row .form-group {
      flex: 1;
    }

    label {
      display: block;
      margin-bottom: 5px;
      font-weight: 600;
      color: #333;
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

    .file-upload {
      border: 2px dashed #ccc;
      border-radius: 8px;
      padding: 40px;
      text-align: center;
      cursor: pointer;
      background: #fafafa;
      transition: all 0.3s ease;
    }

    .file-upload:hover {
      border-color: #007bff;
      background: #f0f8ff;
    }

    .upload-content {
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    .upload-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }

    .upload-text {
      font-size: 16px;
      color: #333;
      margin: 8px 0;
    }

    .upload-hint {
      font-size: 14px;
      color: #666;
      margin: 8px 0;
    }

    .selected-file {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 16px;
      padding: 8px 16px;
      background: #e8f5e8;
      border-radius: 4px;
      font-size: 14px;
    }

    .remove-file-btn {
      background: none;
      border: none;
      color: #dc3545;
      cursor: pointer;
      font-size: 18px;
      padding: 0;
      margin-left: 8px;
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
      align-items: flex-end;
    }

    .extension-item .form-group {
      flex: 1;
      margin-bottom: 0;
    }

    .remove-btn {
      margin-left: 10px;
    }

    .chip-container {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
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
      font-weight: 600;
    }

    .btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .btn-primary {
      background-color: #007bff;
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background-color: #0056b3;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-secondary:hover:not(:disabled) {
      background-color: #545b62;
    }

    .btn-danger {
      background-color: #dc3545;
      color: white;
    }

    .btn-danger:hover:not(:disabled) {
      background-color: #c82333;
    }

    .btn-sm {
      padding: 5px 10px;
      font-size: 12px;
    }

    .form-hint {
      display: block;
      font-size: 12px;
      color: #6c757d;
      margin-top: 5px;
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

    @media (max-width: 768px) {
      .container {
        padding: 16px;
      }

      .form-row {
        flex-direction: column;
        gap: 0;
      }
      
      .extension-item {
        flex-direction: column;
        gap: 10px;
      }
      
      .form-actions {
        flex-direction: column;
      }

      .file-upload {
        padding: 24px;
      }
    }
  `]
})
export class RequestCertificateComponent implements OnInit {
  @ViewChild('notAfterCSRModel') dateNotAfterCSRModel!: NgModel;
  @ViewChild('notBeforeModel') dateNotBeforeModel!: NgModel;
  @ViewChild('notAfterModel') dateNotAfterModel!: NgModel;

  private certificatesService = inject(CertificatesService);
  private certificateRequestsService = inject(CertificateRequestsService);
  private authService = inject(AuthService);
  private toastr = inject(ToastrService);

  loading = false;
  signingCertificates: any[] = [];
  selectedCertificate: any = null;
  selectedCertificateId: string = '';
  activeTab = 'upload';
  error: string | null = null;
  success: string | null = null;
  
  // CSR Upload
  csrFile: File | null = null;
  privateKeyFile: File | null = null;
  csrFileName: string = '';
  privateKeyFileName: string = '';
  isDragging = false;
  
  // Form fields
  commonName = '';
  organization = '';
  organizationalUnit = '';
  email = '';
  country = '';
  dateNotBefore: string = '';
  dateNotAfter: string = '';
  
  // Extensions
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

  ngOnInit() {
    this.loadSigningCertificates();
    this.setDefaultDates();
  }

  loadSigningCertificates() {
    this.certificatesService.getAllCACertificates().subscribe({
      next: (certificates) => {
        this.signingCertificates = certificates;
      },
      error: (error) => {
        console.error('Error loading CA certificates:', error);
        this.toastr.error('Error loading signing certificates');
      }
    });
  }

  setDefaultDates() {
    const now = new Date();
    const oneYearFromNow = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
    
    // Format dates for datetime-local input (YYYY-MM-DDTHH:MM)
    this.dateNotBefore = now.toISOString().slice(0, 16);
    this.dateNotAfter = oneYearFromNow.toISOString().slice(0, 16);
  }

  // File upload methods
  onFileChosen(event: any, fileType: 'csr' | 'privateKey') {
    const file = event.target.files[0];
    if (file) {
      if (fileType === 'csr') {
        this.csrFile = file;
        this.csrFileName = file.name;
      } else if (fileType === 'privateKey') {
        this.privateKeyFile = file;
        this.privateKeyFileName = file.name;
      }
    }
  }

  onDrop(event: DragEvent, fileType: 'csr' | 'privateKey') {
    event.preventDefault();
    this.isDragging = false;
    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      if (fileType === 'csr') {
        this.csrFile = files[0];
        this.csrFileName = files[0].name;
      } else if (fileType === 'privateKey') {
        this.privateKeyFile = files[0];
        this.privateKeyFileName = files[0].name;
      }
    }
  }

  onDragOver(event: DragEvent) {
    event.preventDefault();
    this.isDragging = true;
  }

  onDragLeave(event: DragEvent) {
    event.preventDefault();
    this.isDragging = false;
  }

  removeFile(event: Event, fileType: 'csr' | 'privateKey') {
    event.stopPropagation();
    if (fileType === 'csr') {
      this.csrFile = null;
      this.csrFileName = '';
    } else if (fileType === 'privateKey') {
      this.privateKeyFile = null;
      this.privateKeyFileName = '';
    }
  }

  // Form submission methods
  onSubmitCSR(form: NgForm) {
    if (form.invalid || !this.csrFile || !this.privateKeyFile || !this.selectedCertificate) {
      this.error = 'Please select a valid signing certificate and upload both CSR and private key files';
      return;
    }

    this.loading = true;
    this.error = null;
    this.success = null;
    
    const formData = new FormData();
    formData.append('csrFile', this.csrFile);
    formData.append('privateKeyFile', this.privateKeyFile);
    formData.append('signingCertificate', this.selectedCertificate.serialNumber);
    formData.append('notAfter', this.dateNotAfter || '');

    this.certificateRequestsService.uploadCSR(formData).subscribe({
      next: (response) => {
        this.success = 'CSR uploaded successfully!';
        this.resetForm();
      },
      error: (error) => {
        console.error('Error uploading CSR:', error);
        this.error = 'Error uploading CSR. Please try again.';
      },
      complete: () => {
        this.loading = false;
      }
    });
  }

  onSubmit(form: NgForm) {
    if (form.invalid || !this.selectedCertificate) {
      this.error = 'Please select a valid signing certificate';
      return;
    }

    this.loading = true;
    this.error = null;
    this.success = null;
    
    const request: CreateCertificateRequest = {
      signingCertificate: this.selectedCertificate.serialNumber,
      commonName: this.commonName,
      organization: this.organization,
      organizationalUnit: this.organizationalUnit,
      email: this.email,
      country: this.country,
      notBefore: this.dateNotBefore || undefined,
      notAfter: this.dateNotAfter || undefined,
      keyUsage: this.getKeyUsageValues(),
      extendedKeyUsage: this.getExtendedKeyUsageValues(),
      subjectAlternativeNames: this.getSubjectAlternativeNames(),
      issuerAlternativeNames: this.getIssuerAlternativeNames(),
      nameConstraints: this.getNameConstraints(),
      basicConstraints: this.getBasicConstraints(),
      certificatePolicy: this.getCertificatePolicy()
    };

    this.certificateRequestsService.createFormBasedCSR(request).subscribe({
      next: (response) => {
        this.success = 'Certificate request with key pair generated successfully!';
        this.resetForm();
      },
      error: (error) => {
        console.error('Error creating certificate request:', error);
        this.error = 'Error creating certificate request. Please try again.';
      },
      complete: () => {
        this.loading = false;
      }
    });
  }

  // Extension methods
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

  // SAN methods
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

  // Helper methods
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
      const bc = bcExt.value;
      return JSON.stringify({ isCa: bc.isCa, pathLen: bc.pathLen });
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

  onCountryInput(event: any) {
    this.country = event.target.value.toUpperCase();
  }

  onCertificateChange(event: any) {
    const certificateId = event.target.value;
    this.selectedCertificate = this.signingCertificates.find(cert => cert.serialNumber === certificateId) || null;
  }

  revalidateDates() {
    // Implementation for date validation
  }

  resetForm() {
    this.commonName = '';
    this.organization = '';
    this.organizationalUnit = '';
    this.email = '';
    this.country = '';
    this.dateNotBefore = '';
    this.dateNotAfter = '';
    this.extensions = [];
    this.csrFile = null;
    this.privateKeyFile = null;
    this.csrFileName = '';
    this.privateKeyFileName = '';
    this.selectedCertificate = null;
    this.selectedCertificateId = '';
    this.error = null;
    this.success = null;
    this.setDefaultDates();
  }
}