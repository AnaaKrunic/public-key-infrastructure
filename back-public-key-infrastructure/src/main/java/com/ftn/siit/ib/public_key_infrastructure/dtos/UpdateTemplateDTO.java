package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;

@Data
public class UpdateTemplateDTO {
    private String name;
    private String commonNamePattern;
    private String sanPattern;
    private Integer ttlDays;
    private String keyUsage;
    private String extendedKeyUsage;
}

