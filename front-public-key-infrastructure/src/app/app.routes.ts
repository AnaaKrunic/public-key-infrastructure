import { Routes } from '@angular/router';
import { authGuard, noAuthGuard } from './services/auth/auth.guard';
import { Role } from './models/Role';

export const routes: Routes = [
  // Public routes
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', loadComponent: () => import('./login/login.component').then(m => m.LoginComponent), canActivate: [noAuthGuard] },
  { path: 'register', loadComponent: () => import('./registration/registration.component').then(m => m.RegistrationComponent), canActivate: [noAuthGuard] },
  { path: 'crl', loadComponent: () => import('./components/common/crl-page/crl-page.component').then(m => m.CrlPageComponent) },
  
  // Admin routes
  { 
    path: 'admin/certificates', 
    loadComponent: () => import('./components/admin/all-certificates/all-certificates.component').then(m => m.AllCertificatesComponent), 
    canActivate: [authGuard],
    data: { roles: ['ADMIN'] as Role[] }
  },
  { 
    path: 'admin/issue', 
    loadComponent: () => import('./components/common/issue-certificate/issue-certificate.component').then(m => m.IssueCertificateComponent), 
    canActivate: [authGuard],
    data: { roles: ['ADMIN', 'CA_USER'] as Role[] }
  },
  { 
    path: 'admin/ca-users', 
    loadComponent: () => import('./components/admin/ca-user-management/ca-user-management.component').then(m => m.CaUserManagementComponent), 
    canActivate: [authGuard],
    data: { roles: ['ADMIN'] as Role[] }
  },
  
  // CA User routes
  { 
    path: 'ca/certificates', 
    loadComponent: () => import('./components/ca-user/signed-certificates/signed-certificates.component').then(m => m.SignedCertificatesComponent), 
    canActivate: [authGuard],
    data: { roles: ['CA_USER'] as Role[] }
  },
  { 
    path: 'ca/pending-csrs', 
    loadComponent: () => import('./components/ca-user/certificate-requests/certificate-requests.component').then(m => m.CertificateRequestsComponent), 
    canActivate: [authGuard],
    data: { roles: ['CA_USER'] as Role[] }
  },
  { 
    path: 'ca/templates', 
    loadComponent: () => import('./components/ca-user/template-management/template-management.component').then(m => m.TemplateManagementComponent), 
    canActivate: [authGuard],
    data: { roles: ['CA_USER', 'ADMIN'] as Role[] }
  },
  
  // EE User routes
  { 
    path: 'my-certificates', 
    loadComponent: () => import('./components/ee-user/my-certificates/my-certificates.component').then(m => m.MyCertificatesComponent), 
    canActivate: [authGuard],
    data: { roles: ['EE_USER', 'CA_USER'] as Role[] }
  },
  { 
    path: 'request-certificate', 
    loadComponent: () => import('./components/ee-user/request-certificate/request-certificate.component').then(m => m.RequestCertificateComponent), 
    canActivate: [authGuard],
    data: { roles: ['EE_USER'] as Role[] }
  },
  
  // Dashboard route
  { 
    path: 'dashboard', 
    loadComponent: () => import('./dashboard/dashboard.component').then(m => m.DashboardComponent), 
    canActivate: [authGuard] 
  },
  
  // Role-based redirect
  { 
    path: 'role-redirect', 
    loadComponent: () => import('./components/common/role-redirect/role-redirect.component').then(m => m.RoleRedirectComponent), 
    canActivate: [authGuard] 
  },
  
  // Catch all
  { path: '**', redirectTo: 'login' }
];
