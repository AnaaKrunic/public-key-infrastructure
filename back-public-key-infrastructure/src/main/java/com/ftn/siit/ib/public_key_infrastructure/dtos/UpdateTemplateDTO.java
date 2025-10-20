package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Size;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateTemplateDTO {
    
    @NotBlank(message = "Template name is required")
    @Size(max = 100, message = "Template name must not exceed 100 characters")
    private String name;
    
    @NotBlank(message = "CN regex pattern is required")
    @Size(max = 500, message = "CN regex pattern must not exceed 500 characters")
    private String cnRegex;
    
    @NotBlank(message = "SAN regex pattern is required")
    @Size(max = 500, message = "SAN regex pattern must not exceed 500 characters")
    private String sanRegex;
    
    @NotNull(message = "TTL is required")
    @Min(value = 1, message = "TTL must be at least 1 day")
    @Max(value = 3650, message = "TTL must not exceed 3650 days (10 years)")
    private Integer ttl;
    
    @NotBlank(message = "Key Usage is required")
    @Size(max = 500, message = "Key Usage must not exceed 500 characters")
    private String keyUsage;
    
    @NotBlank(message = "Extended Key Usage is required")
    @Size(max = 500, message = "Extended Key Usage must not exceed 500 characters")
    private String extendedKeyUsage;
}