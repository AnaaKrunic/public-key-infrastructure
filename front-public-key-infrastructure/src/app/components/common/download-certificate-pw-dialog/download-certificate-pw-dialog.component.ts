import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-download-certificate-pw-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatIconModule
  ],
  template: `
    <div class="dialog-container">
      <h2 mat-dialog-title>Download Certificate</h2>
      
      <div mat-dialog-content class="download-content">
        <p>Enter a password to protect the PKCS#12 file:</p>
        
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Password</mat-label>
          <input 
            matInput 
            type="password"
            [(ngModel)]="password" 
            placeholder="Enter password for PKCS#12 file"
            required
            minlength="6">
          <mat-hint>Minimum 6 characters</mat-hint>
        </mat-form-field>
        
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Confirm Password</mat-label>
          <input 
            matInput 
            type="password"
            [(ngModel)]="confirmPassword" 
            placeholder="Confirm password"
            required>
        </mat-form-field>
        
        <div *ngIf="password && confirmPassword && password !== confirmPassword" class="error-message">
          <mat-icon>error</mat-icon>
          Passwords do not match
        </div>
        
        <div class="info-message">
          <mat-icon>info</mat-icon>
          <span>The certificate will be downloaded as a PKCS#12 (.pfx) file.</span>
        </div>
      </div>
      
      <div mat-dialog-actions class="dialog-actions">
        <button mat-button (click)="onCancel()">Cancel</button>
        <button 
          mat-raised-button 
          color="primary" 
          (click)="onConfirm()"
          [disabled]="!isFormValid()">
          Download
        </button>
      </div>
    </div>
  `,
  styles: [`
    .dialog-container {
      min-width: 500px;
      max-width: 600px;
      max-height: 90vh;
      margin: 0;
      padding: 0;
    }
    
    h2[mat-dialog-title] {
      margin: 0 0 24px 0;
      padding: 0 0 16px 0;
      border-bottom: 2px solid #007bff;
      color: #007bff;
      font-size: 24px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    
    h2[mat-dialog-title]::before {
      content: "🔒";
      font-size: 20px;
    }
    
    .download-content {
      padding: 8px 0;
    }
    
    .download-content p {
      margin-bottom: 32px;
      color: #495057;
      font-size: 16px;
      line-height: 1.5;
      padding: 16px;
      background: #e7f3ff;
      border: 1px solid #b3d9ff;
      border-radius: 8px;
      border-left: 4px solid #007bff;
    }
    
    .full-width {
      width: 100%;
      margin-bottom: 20px;
    }
    
    .full-width mat-form-field {
      width: 100%;
    }
    
    .full-width mat-form-field .mat-mdc-form-field-subscript-wrapper {
      margin-top: 8px;
    }
    
    .full-width mat-form-field .mat-mdc-form-field-hint {
      color: #6c757d;
      font-size: 12px;
    }
    
    .full-width input[matInput] {
      font-family: 'Courier New', monospace;
      letter-spacing: 1px;
    }
    
    .error-message {
      display: flex;
      align-items: center;
      gap: 12px;
      color: #dc3545;
      font-size: 14px;
      font-weight: 500;
      margin-bottom: 20px;
      padding: 12px 16px;
      background: #f8d7da;
      border: 1px solid #f5c6cb;
      border-radius: 8px;
      border-left: 4px solid #dc3545;
      animation: shake 0.5s ease-in-out;
    }
    
    .error-message mat-icon {
      color: #dc3545;
      font-size: 20px;
    }
    
    .info-message {
      display: flex;
      align-items: center;
      gap: 12px;
      color: #495057;
      font-size: 14px;
      margin-top: 20px;
      padding: 12px 16px;
      background: #d1ecf1;
      border: 1px solid #bee5eb;
      border-radius: 8px;
      border-left: 4px solid #17a2b8;
    }
    
    .info-message mat-icon {
      color: #17a2b8;
      font-size: 20px;
    }
    
    .dialog-actions {
      justify-content: flex-end;
      gap: 12px;
      padding: 24px 0 0 0;
      border-top: 1px solid #e0e0e0;
      margin-top: 16px;
    }
    
    .dialog-actions button {
      min-width: 120px;
      padding: 12px 24px;
      font-weight: 600;
      border-radius: 6px;
      transition: all 0.2s ease;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .dialog-actions button[mat-button] {
      color: #6c757d;
      border: 1px solid #dee2e6;
    }
    
    .dialog-actions button[mat-button]:hover {
      background: #f8f9fa;
      border-color: #adb5bd;
      transform: translateY(-1px);
    }
    
    .dialog-actions button[mat-raised-button] {
      background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
      color: white;
      box-shadow: 0 2px 8px rgba(0, 123, 255, 0.3);
    }
    
    .dialog-actions button[mat-raised-button]:hover:not(:disabled) {
      background: linear-gradient(135deg, #0056b3 0%, #004085 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 16px rgba(0, 123, 255, 0.4);
    }
    
    .dialog-actions button[mat-raised-button]:disabled {
      background: #6c757d;
      color: #adb5bd;
      box-shadow: none;
      cursor: not-allowed;
    }
    
    /* Form field focus states */
    .full-width mat-form-field.mat-focused .mat-mdc-form-field-focus-overlay {
      background-color: rgba(0, 123, 255, 0.04);
    }
    
    .full-width mat-form-field.mat-focused .mat-mdc-form-field-outline-thick {
      color: #007bff;
    }
    
    /* Password strength indicator */
    .password-strength {
      margin-top: 8px;
      font-size: 12px;
      font-weight: 500;
    }
    
    .password-strength.weak {
      color: #dc3545;
    }
    
    .password-strength.medium {
      color: #ffc107;
    }
    
    .password-strength.strong {
      color: #28a745;
    }
    
    /* Animations */
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      25% { transform: translateX(-5px); }
      75% { transform: translateX(5px); }
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
      .dialog-container {
        min-width: 90vw;
        max-width: 95vw;
      }
      
      .dialog-actions {
        flex-direction: column;
        gap: 8px;
      }
      
      .dialog-actions button {
        width: 100%;
        min-width: auto;
      }
    }
  `]
})
export class DownloadCertificatePwDialogComponent {
  private dialogRef = inject(MatDialogRef<DownloadCertificatePwDialogComponent>);
  
  password: string = '';
  confirmPassword: string = '';

  onCancel(): void {
    this.dialogRef.close();
  }

  onConfirm(): void {
    if (this.isFormValid()) {
      this.dialogRef.close(this.password);
    }
  }

  isFormValid(): boolean {
    return this.password.length >= 6 && 
           this.confirmPassword.length >= 6 && 
           this.password === this.confirmPassword;
  }
}
