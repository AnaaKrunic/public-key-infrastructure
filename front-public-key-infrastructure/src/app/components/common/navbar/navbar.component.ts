import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from '../../../services/auth/auth.service';
import { Role } from '../../../models/Role';
import { BasicUser } from '../../../models/BasicUser';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.css'
})
export class NavbarComponent implements OnInit {
  user: BasicUser | null = null;
  userRole: Role | null = null;
  isLoggedIn = false;

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.authService.user$.subscribe(user => {
      this.user = user;
    });

    this.authService.role$.subscribe(role => {
      this.userRole = role;
    });

    this.authService.isLoggedIn$.subscribe(isLoggedIn => {
      this.isLoggedIn = isLoggedIn;
    });
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/login']);
  }

  hasRole(role: Role): boolean {
    return this.userRole === role;
  }

  hasAnyRole(roles: Role[]): boolean {
    return this.userRole ? roles.includes(this.userRole) : false;
  }

  getDisplayName(): string {
    if (this.user?.name && this.user?.surname) {
      return `${this.user.name} ${this.user.surname}`;
    }
    return this.user?.email || 'User';
  }

  getRoleDisplayName(): string {
    switch (this.userRole) {
      case 'ADMIN':
        return 'Administrator';
      case 'CA_USER':
        return 'CA User';
      case 'EE_USER':
        return 'End Entity User';
      default:
        return 'User';
    }
  }
}
