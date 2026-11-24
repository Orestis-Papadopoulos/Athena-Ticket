package com.example.athenaticket;

import android.nfc.tech.NfcA;
import androidx.annotation.Nullable;
import java.io.IOException;

public class NfcUtils {

    @Nullable
    public static byte[] safeTransceive(NfcA nfcA, byte[] data) {
        try {
            return nfcA.transceive(data);
        } catch (IOException e) {
            // Swallows TagLostException and timeout IOExceptions
            return null;
        }
    }
}
