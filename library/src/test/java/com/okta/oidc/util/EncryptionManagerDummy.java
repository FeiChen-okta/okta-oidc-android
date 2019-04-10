package com.okta.oidc.util;

import com.okta.oidc.storage.security.EncryptionManager;

public class EncryptionManagerDummy implements EncryptionManager {
    @Override
    public String encrypt(String value) {
        return value;
    }

    @Override
    public String decrypt(String value) {
        return value;
    }

    @Override
    public String getHashed(String value) {
        return value;
    }
}
