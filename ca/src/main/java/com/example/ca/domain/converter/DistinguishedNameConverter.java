package com.example.ca.domain.converter;

import com.example.ca.domain.DistinguishedName;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class DistinguishedNameConverter implements AttributeConverter<DistinguishedName, String> {

    @Override
    public String convertToDatabaseColumn(DistinguishedName attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.toRawName();
    }

    @Override
    public DistinguishedName convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) {
            return null;
        }
        return DistinguishedName.from(dbData);
    }
}
