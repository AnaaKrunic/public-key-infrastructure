import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { TemplateService } from '../../../services/template/template.service';
import { CertificatesService } from '../../../services/certificates/certificates.service';
import { Template, CreateTemplateDTO } from '../../../models/Template';
import { Certificate } from '../../../models/Certificate';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-template-management',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, MatFormFieldModule, MatSelectModule, MatChipsModule, MatIconModule, MatButtonModule],
  templateUrl: './template-management.component.html',
  styleUrls: ['./template-management.component.css']
})
export class TemplateManagementComponent implements OnInit {
  templates: Template[] = [];
  availableCAs: Certificate[] = [];
  templateForm: FormGroup;
  isCreating = false;
  editingTemplate: Template | null = null;
  caLoadError = '';

  // Predefined options
  keyUsageOptions = [
    { value: 'digitalSignature', label: 'Digital Signature' },
    { value: 'nonRepudiation', label: 'Non Repudiation' },
    { value: 'keyEncipherment', label: 'Key Encipherment' },
    { value: 'dataEncipherment', label: 'Data Encipherment' },
    { value: 'keyAgreement', label: 'Key Agreement' },
    { value: 'keyCertSign', label: 'Certificate Sign' },
    { value: 'cRLSign', label: 'CRL Sign' },
    { value: 'encipherOnly', label: 'Encipher Only' },
    { value: 'decipherOnly', label: 'Decipher Only' }
  ];

  extendedKeyUsageOptions = [
    { value: 'serverAuth', label: 'Server Authentication' },
    { value: 'clientAuth', label: 'Client Authentication' },
    { value: 'codeSigning', label: 'Code Signing' },
    { value: 'emailProtection', label: 'Email Protection' },
    { value: 'timeStamping', label: 'Time Stamping' },
    { value: 'OCSPSigning', label: 'OCSP Signing' }
  ];

  constructor(
    private templateService: TemplateService,
    private certificatesService: CertificatesService,
    private fb: FormBuilder,
    private toastr: ToastrService
  ) {
    this.templateForm = this.fb.group({
      name: ['', [Validators.required, Validators.maxLength(100)]],
      caIssuerSerialNumber: ['', Validators.required],
      cnRegex: ['', [Validators.required, Validators.maxLength(500)]],
      sanRegex: ['', [Validators.required, Validators.maxLength(500)]],
      ttl: [365, [Validators.required, Validators.min(1), Validators.max(3650)]],
      keyUsage: [[], [Validators.required]],
      extendedKeyUsage: [[], [Validators.required]]
    });
  }

  ngOnInit() {
    this.loadTemplates();
    this.loadAvailableCAs();
  }

  loadTemplates() {
    this.templateService.getAllTemplates().subscribe({
      next: (templates) => {
        this.templates = templates;
      },
      error: (error) => {
        this.toastr.error('Failed to load templates', 'Error');
        console.error('Error loading templates:', error);
      }
    });
  }

  loadAvailableCAs() {
    this.caLoadError = '';
    // Strategy: try current-user scoped first, then global valid signing certs, then fallback to all and filter
    this.certificatesService.getMyValidSigningCertificates().subscribe({
      next: (mine) => {
        const list = (mine || []).filter(c => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE');
        if (list.length > 0) {
          this.availableCAs = list;
        } else {
          this.loadAllValidSigning();
        }
      },
      error: (_) => this.loadAllValidSigning()
    });
  }

  private loadAllValidSigning() {
    this.certificatesService.getAllValidSigningCertificates().subscribe({
      next: (all) => {
        const list = (all || []).filter(c => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE');
        if (list.length > 0) {
          this.availableCAs = list;
        } else {
          this.loadAllAndFilter();
        }
      },
      error: (_) => this.loadAllAndFilter()
    });
  }

  private loadAllAndFilter() {
    this.certificatesService.getAllCertificates(0, 50).subscribe({
      next: (resp) => {
        const items = resp?.content || resp || [];
        const list = items.filter((c: any) => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE');
        this.availableCAs = list;
        if (list.length === 0) {
          this.caLoadError = 'No CA certificates found. Issue a Root/Intermediate CA first.';
        }
      },
      error: (error) => {
        this.caLoadError = 'Failed to load CA certificates.';
        this.toastr.error('Failed to load CA certificates', 'Error');
        console.error('Error loading CA certificates:', error);
      }
    });
  }

  createTemplate() {
    if (this.templateForm.valid) {
      this.isCreating = true;
      const dto: CreateTemplateDTO = {
        name: this.templateForm.value.name,
        caIssuerSerialNumber: this.templateForm.value.caIssuerSerialNumber,
        cnRegex: this.templateForm.value.cnRegex,
        sanRegex: this.templateForm.value.sanRegex,
        ttl: this.templateForm.value.ttl,
        keyUsage: this.toCommaSeparated(this.templateForm.value.keyUsage),
        extendedKeyUsage: this.toCommaSeparated(this.templateForm.value.extendedKeyUsage)
      };
      
      this.templateService.createTemplate(dto).subscribe({
        next: (template) => {
          this.templates.push(template);
          this.templateForm.reset();
          this.templateForm.patchValue({ ttl: 365 }); // Reset to default
          this.isCreating = false;
          this.toastr.success('Template created successfully', 'Success');
        },
        error: (error) => {
          this.isCreating = false;
          this.toastr.error(error.error?.error || 'Failed to create template', 'Error');
          console.error('Error creating template:', error);
        }
      });
    } else {
      this.toastr.warning('Please fill in all required fields', 'Validation Error');
    }
  }

  editTemplate(template: Template) {
    this.editingTemplate = template;
    this.templateForm.patchValue({
      name: template.name,
      cnRegex: template.cnRegex,
      sanRegex: template.sanRegex,
      ttl: template.ttl,
      keyUsage: this.toArray(template.keyUsage),
      extendedKeyUsage: this.toArray(template.extendedKeyUsage)
    });
  }

  updateTemplate() {
    if (this.templateForm.valid && this.editingTemplate) {
      const dto = {
        name: this.templateForm.value.name,
        cnRegex: this.templateForm.value.cnRegex,
        sanRegex: this.templateForm.value.sanRegex,
        ttl: this.templateForm.value.ttl,
        keyUsage: this.toCommaSeparated(this.templateForm.value.keyUsage),
        extendedKeyUsage: this.toCommaSeparated(this.templateForm.value.extendedKeyUsage)
      };
      
      this.templateService.updateTemplate(this.editingTemplate.id, dto).subscribe({
        next: (updatedTemplate) => {
          const index = this.templates.findIndex(t => t.id === updatedTemplate.id);
          if (index !== -1) {
            this.templates[index] = updatedTemplate;
          }
          this.cancelEdit();
          this.toastr.success('Template updated successfully', 'Success');
        },
        error: (error) => {
          this.toastr.error(error.error?.error || 'Failed to update template', 'Error');
          console.error('Error updating template:', error);
        }
      });
    }
  }

  deleteTemplate(template: Template) {
    if (confirm(`Are you sure you want to delete template "${template.name}"?`)) {
      this.templateService.deleteTemplate(template.id).subscribe({
        next: () => {
          this.templates = this.templates.filter(t => t.id !== template.id);
          this.toastr.success('Template deleted successfully', 'Success');
        },
        error: (error) => {
          this.toastr.error(error.error?.error || 'Failed to delete template', 'Error');
          console.error('Error deleting template:', error);
        }
      });
    }
  }

  cancelEdit() {
    this.editingTemplate = null;
    this.templateForm.reset();
    this.templateForm.patchValue({ ttl: 365 });
  }

  testRegex(pattern: string, testValue: string): boolean {
    try {
      const regex = new RegExp(pattern);
      return regex.test(testValue);
    } catch (e) {
      return false;
    }
  }

  getFormControl(name: string) {
    return this.templateForm.get(name);
  }

  private toCommaSeparated(values: string[] | null | undefined): string {
    if (!values || values.length === 0) return '';
    return values.join(',');
  }

  private toArray(value: string | null | undefined): string[] {
    if (!value) return [];
    return value.split(',').map(v => v.trim()).filter(v => !!v);
  }

  getLabelFromKeyUsage(value: string): string {
    const found = this.keyUsageOptions.find(o => o.value === value);
    return found ? found.label : value;
  }

  getLabelFromExtendedKeyUsage(value: string): string {
    const found = this.extendedKeyUsageOptions.find(o => o.value === value);
    return found ? found.label : value;
  }

  removeFromControl(controlName: 'keyUsage' | 'extendedKeyUsage', value: string): void {
    const control = this.getFormControl(controlName);
    if (!control) return;
    const current: string[] = control.value || [];
    control.setValue(current.filter(v => v !== value));
    control.markAsDirty();
    control.updateValueAndValidity();
  }
}
