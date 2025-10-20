import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map, of } from 'rxjs';
import { Template, CreateTemplateDTO, UpdateTemplateDTO, TemplateValidationResult } from '../../models/Template';

@Injectable({
  providedIn: 'root'
})
export class TemplateService {
  private apiUrl = 'http://localhost:8080/api/templates';

  constructor(private http: HttpClient) {}

  // CRUD operations
  createTemplate(dto: CreateTemplateDTO): Observable<Template> {
    return this.http.post<Template>(`${this.apiUrl}/create`, dto);
  }

  getAllTemplates(): Observable<Template[]> {
    return this.http.get<Template[]>(`${this.apiUrl}/all`);
  }

  getTemplatesForCA(caSerialNumber: string): Observable<Template[]> {
    return this.http.get<Template[]>(`${this.apiUrl}/ca/${caSerialNumber}`);
  }

  getTemplateById(id: number): Observable<Template> {
    return this.http.get<Template>(`${this.apiUrl}/${id}`);
  }

  updateTemplate(id: number, dto: UpdateTemplateDTO): Observable<Template> {
    return this.http.put<Template>(`${this.apiUrl}/${id}`, dto);
  }

  deleteTemplate(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }

  // Validation
  validateCN(cn: string, regex: string): Observable<boolean> {
    return this.http.post<{isValid: boolean}>(`${this.apiUrl}/validate-cn`, { cn, regex })
      .pipe(
        map(response => response.isValid)
      );
  }

  validateSAN(san: string, regex: string): Observable<boolean> {
    return this.http.post<{isValid: boolean}>(`${this.apiUrl}/validate-san`, { san, regex })
      .pipe(
        map(response => response.isValid)
      );
  }

  validateTemplate(dto: CreateTemplateDTO): Observable<TemplateValidationResult> {
    // Client-side validation
    const errors: string[] = [];
    
    if (!dto.name?.trim()) {
      errors.push('Template name is required');
    }
    
    if (!dto.caIssuerSerialNumber?.trim()) {
      errors.push('CA issuer serial number is required');
    }
    
    if (!dto.cnRegex?.trim()) {
      errors.push('CN regex is required');
    }
    
    if (!dto.sanRegex?.trim()) {
      errors.push('SAN regex is required');
    }
    
    if (!dto.ttl || dto.ttl < 1 || dto.ttl > 3650) {
      errors.push('TTL must be between 1 and 3650 days');
    }
    
    if (!dto.keyUsage?.trim()) {
      errors.push('Key Usage is required');
    }
    
    if (!dto.extendedKeyUsage?.trim()) {
      errors.push('Extended Key Usage is required');
    }
    
    // Test regex patterns
    try {
      new RegExp(dto.cnRegex);
    } catch (e) {
      errors.push('Invalid CN regex pattern');
    }
    
    try {
      new RegExp(dto.sanRegex);
    } catch (e) {
      errors.push('Invalid SAN regex pattern');
    }
    
    return of({
      isValid: errors.length === 0,
      error: errors.length > 0 ? errors.join(', ') : undefined
    });
  }
}
