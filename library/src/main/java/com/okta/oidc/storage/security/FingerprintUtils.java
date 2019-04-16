package com.okta.oidc.storage.security;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;

/**
 * Created by azret.magometov on 19-Dec-16.
 */

public final class FingerprintUtils {
    private FingerprintUtils() {
    }

    public enum SensorState {
        NOT_SUPPORTED,
        NOT_BLOCKED,
        NO_FINGERPRINTS,
        READY
    }

    public static boolean checkFingerprintCompatibility(@NonNull Context context) {
        return FingerprintManagerCompat.from(context).isHardwareDetected();
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    public static SensorState checkSensorState(@NonNull Context context) {
        if (checkFingerprintCompatibility(context)) {

            KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            if (!keyguardManager.isKeyguardSecure()) {
                return SensorState.NOT_BLOCKED;
            }

            if (!FingerprintManagerCompat.from(context).hasEnrolledFingerprints()) {
                return SensorState.NO_FINGERPRINTS;
            }

            return SensorState.READY;

        } else {
            return SensorState.NOT_SUPPORTED;
        }

    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    public static boolean isSensorStateAt(@NonNull SensorState state, @NonNull Context context) {
        return checkSensorState(context) == state;
    }
}
