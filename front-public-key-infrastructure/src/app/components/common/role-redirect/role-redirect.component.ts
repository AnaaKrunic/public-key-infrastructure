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
    const role = this.authService.getCurrentRole();
    
    switch (role) {
      case 'ADMIN':
        this.router.navigate(['/admin/certificates']);
        break;
      case 'CA_USER':
        this.router.navigate(['/ca/certificates']);
        break;
      case 'EE_USER':
        this.router.navigate(['/my-certificates']);
        break;
      default:
        this.router.navigate(['/login']);
        break;
    }
  }
}
