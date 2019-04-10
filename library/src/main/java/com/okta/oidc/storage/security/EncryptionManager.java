package com.okta.oidc.storage.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public interface EncryptionManager {

    String encrypt(String value) throws GeneralSecurityException, IOException;

    String decrypt(String value) throws GeneralSecurityException, IOException;

    String getHashed(String value) throws NoSuchAlgorithmException, UnsupportedEncodingException;

}
