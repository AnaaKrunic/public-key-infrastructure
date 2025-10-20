import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { CreateCaUser } from '../../models/CreateCaUser';
import { CaUser } from '../../models/CaUser';

@Injectable({
  providedIn: 'root'
})
export class UsersService {
  private readonly API_BASE_URL = 'https://localhost:8443/api';

  constructor(private http: HttpClient) {}

  // Get all CA users (Admin only)
  getAllCaUsers(): Observable<CaUser[]> {
    return this.http.get<CaUser[]>(`${this.API_BASE_URL}/users/get-all-ca-users`);
  }

  // Get valid CA users (Admin only)
  getValidCaUsers(): Observable<CaUser[]> {
    return this.http.get<CaUser[]>(`${this.API_BASE_URL}/users/get-valid-ca-users`);
  }

  // Create CA user (Admin only)
  createCaUser(caUser: CreateCaUser): Observable<any> {
    return this.http.post(`${this.API_BASE_URL}/users/register-ca`, caUser);
  }
}
