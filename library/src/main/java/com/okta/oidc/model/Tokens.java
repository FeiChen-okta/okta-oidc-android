package com.okta.oidc.model;

import android.support.annotation.Nullable;

import com.okta.oidc.net.response.TokenResponse;

public class Tokens {
    private TokenResponse mTokenResponse;

    public Tokens(TokenResponse response) {
        this.mTokenResponse = response;
    }

    public @Nullable
    String getAccessToken() {
        if(mTokenResponse != null) {
            return mTokenResponse.getAccessToken();
        }
        return null;
    }

    public @Nullable
    String getIdToken() {
        if(mTokenResponse != null) {
            return mTokenResponse.getIdToken();
        }
        return null;
    }

    public @Nullable
    String getRefreshToken() {
        if(mTokenResponse != null) {
            return mTokenResponse.getRefreshToken();
        }
        return null;
    }

}
