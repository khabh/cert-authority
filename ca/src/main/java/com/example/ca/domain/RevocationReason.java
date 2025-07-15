package com.example.ca.domain;

import lombok.Getter;

@Getter
public enum RevocationReason {
    KEY_COMPROMISE(true),
    CESSATION_OF_OPERATION(false),
    AFFILIATION_CHANGED(false);

    private final boolean regenerateKey;

    RevocationReason(boolean regenerateKey) {
        this.regenerateKey = regenerateKey;
    }
}