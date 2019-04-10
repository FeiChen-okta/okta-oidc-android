package com.okta.oidc.storage.security;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import androidx.annotation.Nullable;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;

public class SamrtLockEncrtiptionManager implements EncryptionManager {

    private static final String TAG = SamrtLockEncrtiptionManager.class.getSimpleName();

    private static final String KEY_ALIAS = "key_for_pin";
    private static final String KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private KeyStore mKeyStore;
    private KeyPairGenerator mKeyPairGenerator;
    private Cipher mCipher;

    @Override
    public String encrypt(String inputString) throws GeneralSecurityException {
        if (prepare() && initCipher(Cipher.ENCRYPT_MODE)) {
            byte[] bytes = mCipher.doFinal(inputString.getBytes());
            return Base64.encodeToString(bytes, Base64.NO_WRAP);
        }
        return inputString;
    }

    @Override
    public String decrypt(String encodedString) throws GeneralSecurityException {
        if (prepare() && initCipher(Cipher.ENCRYPT_MODE)) {
            byte[] bytes = Base64.decode(encodedString, Base64.NO_WRAP);
            return new String(mCipher.doFinal(bytes));
        }
        return encodedString;
    }

    private boolean prepare() {
        return getKeyStore() && getCipher() && getKey();
    }


    private boolean getKeyStore() {
        try {
            mKeyStore = KeyStore.getInstance(KEY_STORE);
            mKeyStore.load(null);
            return true;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.d(TAG, "getKeyStore: ", e);
        }
        return false;
    }


    @TargetApi(Build.VERSION_CODES.M)
    private boolean getKeyPairGenerator() {
        try {
            mKeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEY_STORE);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            Log.e(TAG, "getKeyPairGenerator: ", e);
        }
        return false;
    }


    @SuppressLint("GetInstance")
    private boolean getCipher() {
        try {
            mCipher = Cipher.getInstance(TRANSFORMATION);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            Log.e(TAG, "getCipher: ", e);
        }
        return false;
    }

    private boolean getKey() {
        try {
            return mKeyStore.containsAlias(KEY_ALIAS) || generateNewKey();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;

    }


    @TargetApi(Build.VERSION_CODES.M)
    private boolean generateNewKey() {

        if (getKeyPairGenerator()) {

            try {
                mKeyPairGenerator.initialize(
                        new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                                .setUserAuthenticationRequired(true)
                                .build());
                mKeyPairGenerator.generateKeyPair();
                return true;
            } catch (InvalidAlgorithmParameterException e) {
                Log.e(TAG, "generateNewKey: ", e);
            }
        }
        return false;
    }


    private boolean initCipher(int mode) {
        try {
            mKeyStore.load(null);

            switch (mode) {
                case Cipher.ENCRYPT_MODE:
                    initEncodeCipher(mode);
                    break;

                case Cipher.DECRYPT_MODE:
                    initDecodeCipher(mode);
                    break;
                default:
                    return false; //this cipher is only for encode\decode
            }
            return true;

        } catch (KeyPermanentlyInvalidatedException exception) {
            deleteInvalidKey();

        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException |
                NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void initDecodeCipher(int mode) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException {
        PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_ALIAS, null);
        mCipher.init(mode, key);
    }

    private void initEncodeCipher(int mode) throws KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        PublicKey key = mKeyStore.getCertificate(KEY_ALIAS).getPublicKey();

        // workaround for using public key
        // from https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
        PublicKey unrestricted = KeyFactory.getInstance(key.getAlgorithm()).generatePublic(new X509EncodedKeySpec(key.getEncoded()));
        // from https://code.google.com/p/android/issues/detail?id=197719
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

        mCipher.init(mode, unrestricted, spec);
    }

    public void deleteInvalidKey() {
        if (getKeyStore()) {
            try {
                mKeyStore.deleteEntry(KEY_ALIAS);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }
    }

    @Nullable
    public FingerprintManagerCompat.CryptoObject getCryptoObject() {
        if (prepare() && initCipher(Cipher.DECRYPT_MODE)) {
            return new FingerprintManagerCompat.CryptoObject(mCipher);
        }
        return null;
    }

    @Override
    public String getHashed(String value) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return null;
    }
}
