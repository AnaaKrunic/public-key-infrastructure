import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { UsersService } from '../../../services/users/users.service';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { CaUser } from '../../../models/CaUser';
import { CreateCaUser } from '../../../models/CreateCaUser';
import { Certificate } from '../../../models/Certificate';

@Component({
  selector: 'app-ca-user-management',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="container">
      <h1>CA User Management</h1>
      
      <div class="actions">
        <button (click)="showCreateModal()" class="btn btn-primary">
          Create CA User
        </button>
        <button (click)="refreshUsers()" class="btn btn-secondary">
          Refresh
        </button>
      </div>

      <div *ngIf="loading" class="loading">
        Loading CA users...
      </div>

      <div *ngIf="error" class="error">
        {{ error }}
      </div>

      <div *ngIf="caUsers.length > 0" class="users-table">
        <h2>CA Users</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Organization</th>
              <th>Valid From</th>
              <th>Valid Until</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let user of caUsers">
              <td>{{ user.firstName }} {{ user.lastName }}</td>
              <td>{{ user.email }}</td>
              <td>{{ user.organization }}</td>
              <td>{{ formatDate(user.minValidFrom) }}</td>
              <td>{{ formatDate(user.maxValidUntil) }}</td>
              <td>
                <button (click)="assignCertificate(user)" class="btn btn-sm btn-primary">
                  Assign Certificate
                </button>
                <button (click)="viewUserDetails(user)" class="btn btn-sm btn-secondary">
                  Details
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div *ngIf="!loading && !error && caUsers.length === 0" class="no-data">
        No CA users found.
      </div>

      <!-- Create CA User Modal -->
      <div *ngIf="showCreateUserModal" class="modal-overlay" (click)="closeCreateModal()">
        <div class="modal" (click)="$event.stopPropagation()">
          <h3>Create CA User</h3>
          <form (ngSubmit)="createCaUser()" #createForm="ngForm">
            <div class="form-group">
              <label for="email">Email *</label>
              <input 
                type="email" 
                id="email" 
                name="email" 
                [(ngModel)]="newCaUser.email" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="password">Password *</label>
              <input 
                type="password" 
                id="password" 
                name="password" 
                [(ngModel)]="newCaUser.password" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="firstName">First Name *</label>
              <input 
                type="text" 
                id="firstName" 
                name="firstName" 
                [(ngModel)]="newCaUser.firstName" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="lastName">Last Name *</label>
              <input 
                type="text" 
                id="lastName" 
                name="lastName" 
                [(ngModel)]="newCaUser.lastName" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="organization">Organization *</label>
              <input 
                type="text" 
                id="organization" 
                name="organization" 
                [(ngModel)]="newCaUser.organization" 
                required
                class="form-control">
            </div>
            <div class="form-group">
              <label for="initialSigningCertificateId">Initial Signing Certificate *</label>
              <select 
                id="initialSigningCertificateId" 
                name="initialSigningCertificateId" 
                [(ngModel)]="newCaUser.initialSigningCertificateId" 
                required
                class="form-control">
                <option value="">Select a certificate</option>
                <option *ngFor="let cert of signingCertificates" [value]="cert.id">
                  {{ cert.subjectCN }} ({{ cert.serialNumber }})
                </option>
              </select>
            </div>
            <div class="form-actions">
              <button type="submit" [disabled]="!createForm.form.valid || creating" class="btn btn-primary">
                {{ creating ? 'Creating...' : 'Create User' }}
              </button>
              <button type="button" (click)="closeCreateModal()" class="btn btn-secondary">
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>

      <!-- Assign Certificate Modal -->
      <div *ngIf="showAssignModal" class="modal-overlay" (click)="closeAssignModal()">
        <div class="modal" (click)="$event.stopPropagation()">
          <h3>Assign Certificate to {{ selectedUser?.firstName }} {{ selectedUser?.lastName }}</h3>
          <form (ngSubmit)="assignCertificateToUser()" #assignForm="ngForm">
            <div class="form-group">
              <label for="certificateSerialNumber">Certificate *</label>
              <select 
                id="certificateSerialNumber" 
                name="certificateSerialNumber" 
                [(ngModel)]="selectedCertificateSerialNumber" 
                required
                class="form-control">
                <option value="">Select a certificate</option>
                <option *ngFor="let cert of availableCertificates" [value]="cert.serialNumber">
                  {{ cert.subjectCN }} ({{ cert.serialNumber }})
                </option>
              </select>
            </div>
            <div class="form-actions">
              <button type="submit" [disabled]="!assignForm.form.valid || assigning" class="btn btn-primary">
                {{ assigning ? 'Assigning...' : 'Assign Certificate' }}
              </button>
              <button type="button" (click)="closeAssignModal()" class="btn btn-secondary">
                Cancel
              </button>
            </div>
          </form>
        </div>
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

    .btn-primary {
      background-color: #007bff;
      color: white;
    }

    .btn-secondary {
      background-color: #6c757d;
      color: white;
    }

    .btn-sm {
      padding: 4px 8px;
      font-size: 11px;
      margin-right: 5px;
    }

    .loading, .error, .no-data {
      text-align: center;
      padding: 20px;
      font-size: 16px;
    }

    .error {
      color: #dc3545;
    }

    .users-table {
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

    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }

    .modal {
      background: white;
      padding: 20px;
      border-radius: 8px;
      max-width: 500px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
    }

    .form-group {
      margin-bottom: 15px;
    }

    label {
      display: block;
      margin-bottom: 5px;
      font-weight: 600;
    }

    .form-control {
      width: 100%;
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
    }

    .form-actions {
      margin-top: 20px;
      display: flex;
      gap: 10px;
    }
  `]
})
export class CaUserManagementComponent implements OnInit {
  caUsers: CaUser[] = [];
  signingCertificates: Certificate[] = [];
  availableCertificates: Certificate[] = [];
  loading = false;
  error: string | null = null;
  showCreateUserModal = false;
  showAssignModal = false;
  creating = false;
  assigning = false;
  selectedUser: CaUser | null = null;
  selectedCertificateSerialNumber = '';

  newCaUser: CreateCaUser = {
    email: '',
    password: '',
    firstName: '',
    lastName: '',
    organization: '',
    initialSigningCertificateId: 0
  };

  constructor(
    private usersService: UsersService,
    private certificatesService: CertificatesService
  ) {}

  ngOnInit(): void {
    this.loadCaUsers();
    this.loadSigningCertificates();
  }

  loadCaUsers(): void {
    this.loading = true;
    this.error = null;

    this.usersService.getAllCaUsers().subscribe({
      next: (users) => {
        this.caUsers = users;
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to load CA users';
        this.loading = false;
        console.error('Error loading CA users:', err);
      }
    });
  }

  loadSigningCertificates(): void {
    this.certificatesService.getAllValidSigningCertificates().subscribe({
      next: (certs) => {
        this.signingCertificates = certs;
      },
      error: (err) => {
        console.error('Error loading signing certificates:', err);
      }
    });
  }

  refreshUsers(): void {
    this.loadCaUsers();
  }

  showCreateModal(): void {
    this.newCaUser = {
      email: '',
      password: '',
      firstName: '',
      lastName: '',
      organization: '',
      initialSigningCertificateId: 0
    };
    this.showCreateUserModal = true;
  }

  closeCreateModal(): void {
    this.showCreateUserModal = false;
  }

  createCaUser(): void {
    this.creating = true;

    this.usersService.createCaUser(this.newCaUser).subscribe({
      next: () => {
        this.creating = false;
        this.closeCreateModal();
        this.loadCaUsers();
      },
      error: (err) => {
        this.creating = false;
        console.error('Error creating CA user:', err);
        alert('Failed to create CA user');
      }
    });
  }

  assignCertificate(user: CaUser): void {
    this.selectedUser = user;
    this.selectedCertificateSerialNumber = '';
    
    // Load available certificates for this user
    this.certificatesService.getSigningCertificatesCaUserDoesntHave(user.id.toString()).subscribe({
      next: (certs) => {
        this.availableCertificates = certs;
        this.showAssignModal = true;
      },
      error: (err) => {
        console.error('Error loading available certificates:', err);
        alert('Failed to load available certificates');
      }
    });
  }

  closeAssignModal(): void {
    this.showAssignModal = false;
    this.selectedUser = null;
    this.selectedCertificateSerialNumber = '';
  }

  assignCertificateToUser(): void {
    if (!this.selectedUser) return;

    this.assigning = true;

    this.certificatesService.addCertificateToCaUser(
      this.selectedUser.id.toString(),
      this.selectedCertificateSerialNumber
    ).subscribe({
      next: () => {
        this.assigning = false;
        this.closeAssignModal();
        this.loadCaUsers();
      },
      error: (err) => {
        this.assigning = false;
        console.error('Error assigning certificate:', err);
        alert('Failed to assign certificate');
      }
    });
  }

  viewUserDetails(user: CaUser): void {
    // TODO: Implement user details modal
    console.log('View details for user:', user);
  }

  formatDate(dateString?: string): string {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString();
  }
}
