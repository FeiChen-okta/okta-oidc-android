package com.okta.oidc.model;


import android.support.annotation.NonNull;

import java.util.Map;

public class AuthenticatePayload {
    private Map<String, String> mAdditionalParams;
    private String mState;
    private String mLoginHint;

    private AuthenticatePayload(Builder builder) {
        this.mAdditionalParams = builder.mAdditionalParams;
        this.mState = builder.mState;
        this.mLoginHint = builder.mLoginHint;
    }

    public Map<String, String> getAdditionalParams() {
        return mAdditionalParams;
    }

    public String getState() {
        return mState;
    }

    public String getLoginHint() {
        return mLoginHint;
    }

    public static class Builder {
        private Map<String, String> mAdditionalParams;
        private String mState;
        private String mLoginHint;

        public Builder() { }

        public AuthenticatePayload create() {
            return new AuthenticatePayload(this);
        }


        public Builder withParameters(@NonNull Map<String, String> parameters) {
            mAdditionalParams = parameters;
            return this;
        }

        public Builder withState(@NonNull String state) {
            mState = state;
            return this;
        }

        public Builder withLoginHint(@NonNull String loginHint) {
            mLoginHint = loginHint;
            return this;
        }
    }
}
