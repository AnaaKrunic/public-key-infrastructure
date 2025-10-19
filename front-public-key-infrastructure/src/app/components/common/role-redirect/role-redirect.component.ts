import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../../services/auth/auth.service';
import { Role } from '../../../models/Role';

@Component({
  selector: 'app-role-redirect',
  standalone: true,
  imports: [],
  template: '<div>Redirecting...</div>'
})
export class RoleRedirectComponent implements OnInit {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    console.log('RoleRedirectComponent: ngOnInit called');
    const role = this.authService.getCurrentRole();
    console.log('RoleRedirectComponent: Current role:', role);
    console.log('RoleRedirectComponent: Is logged in:', this.authService.isLoggedIn);
    
    switch (role) {
      case 'ADMIN':
        console.log('RoleRedirectComponent: Redirecting to admin/certificates');
        this.router.navigate(['/admin/certificates']);
        break;
      case 'CA_USER':
        console.log('RoleRedirectComponent: Redirecting to ca/certificates');
        this.router.navigate(['/ca/certificates']);
        break;
      case 'EE_USER':
        console.log('RoleRedirectComponent: Redirecting to my-certificates');
        this.router.navigate(['/my-certificates']);
        break;
      default:
        console.log('RoleRedirectComponent: No valid role, redirecting to login');
        this.router.navigate(['/login']);
        break;
    }
  }
}
