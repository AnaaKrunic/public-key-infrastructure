import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatInputModule } from '@angular/material/input';

@Component({
  selector: 'app-revoke-certificate-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatButtonModule,
    MatFormFieldModule,
    MatSelectModule,
    MatInputModule
  ],
  template: `
    <div class="modal-content">
      <h3>Revoke Certificate</h3>
      
      <form (ngSubmit)="onConfirm()" #revokeForm="ngForm">
        <div class="form-group">
          <label for="revocationReason">Revocation Reason *</label>
          <select 
            id="revocationReason" 
            name="revocationReason" 
            [(ngModel)]="selectedReason" 
            required
            class="form-control">
            <option value="">Select a reason</option>
            <option value="UNSPECIFIED">Unspecified</option>
            <option value="KEY_COMPROMISE">Key Compromise</option>
            <option value="CA_COMPROMISE">CA Compromise</option>
            <option value="AFFILIATION_CHANGED">Affiliation Changed</option>
            <option value="SUPERSEDED">Superseded</option>
            <option value="CESSATION_OF_OPERATION">Cessation of Operation</option>
            <option value="CERTIFICATE_HOLD">Certificate Hold</option>
            <option value="REMOVE_FROM_CRL">Remove from CRL</option>
            <option value="PRIVILEGE_WITHDRAWN">Privilege Withdrawn</option>
            <option value="AA_COMPROMISE">AA Compromise</option>
          </select>
        </div>
        
        <div class="form-actions">
          <button type="submit" [disabled]="!revokeForm.form.valid" class="btn btn-danger">
            Revoke Certificate
          </button>
          <button type="button" (click)="onCancel()" class="btn btn-secondary">
            Cancel
          </button>
        </div>
      </form>
    </div>
  `,
  styles: [`
    .modal-content {
      padding: 20px;
      min-width: 400px;
    }
    
    h3 {
      margin: 0 0 20px 0;
      color: #333;
      font-size: 20px;
      font-weight: 600;
    }
    
    .form-group {
      margin-bottom: 15px;
    }
    
    .form-group label {
      display: block;
      margin-bottom: 5px;
      font-weight: 600;
      color: #333;
    }
    
    .form-control {
      width: 100%;
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }
    
    .form-control:focus {
      outline: none;
      border-color: #3498db;
      box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
    }
    
    .form-actions {
      margin-top: 20px;
      display: flex;
      gap: 10px;
      justify-content: flex-end;
    }
    
    .form-actions button {
      min-width: 100px;
    }
  `]
})
export class RevokeCertificateDialogComponent {
  private dialogRef = inject(MatDialogRef<RevokeCertificateDialogComponent>);
  
  selectedReason: string = '';

  onCancel(): void {
    this.dialogRef.close();
  }

  onConfirm(): void {
    if (this.selectedReason) {
      this.dialogRef.close({
        revocationReason: this.selectedReason
      });
    }
  }
}
