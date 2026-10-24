package com.example.athenaticket;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareUltralight;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private NfcAdapter nfcAdapter;
    private final ExecutorService executor =
            Executors.newSingleThreadExecutor();
    private PendingIntent pendingIntent;
    private TextView txtResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtResult = findViewById(R.id.txtResult);
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        if (nfcAdapter == null) {
            txtResult.setText("NFC is not supported");
            return;
        }

        Intent intent = new Intent(this, getClass())
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);

        pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT
                        | PendingIntent.FLAG_MUTABLE
        );

        if (!nfcAdapter.isEnabled()) {
            txtResult.setText("Please enable NFC in Settings");
        }
        handleIntent(getIntent());
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (nfcAdapter != null && nfcAdapter.isEnabled()) {
            nfcAdapter.enableForegroundDispatch(
                    this, pendingIntent, null, null);
        }
    }

    @Override
    protected void onPause() {
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
        super.onPause();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (!NfcAdapter.ACTION_TAG_DISCOVERED.equals(action)
                && !NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)
                && !NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {
            return;
        }

        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag == null) return;
        StringBuilder result = new StringBuilder();
        result.append("NFC tag detected!\n");

        byte[] uid = tag.getId();
        StringBuilder hex = new StringBuilder();
        for (byte b : uid) {
            hex.append(String.format("%02X ", b & 0xFF));
        }
        notify(hex.toString().trim());

        //

        MifareUltralight mifare = MifareUltralight.get(tag);
        if (mifare == null) {
            notify("Not recognized as MIFARE Ultralight.");
            return;
        }

        // tested - working
//        executor.execute(() -> {
//            try {
//                mifare.connect();
//                mifare.setTimeout(5000);
//                byte[] command = new byte[] {
//                        (byte) 0x1b,
//                        (byte) 0x60,
//                        (byte) 0x09,
//                        (byte) 0xad,
//                        (byte) 0xb6
//                };
//                String versionResponse;
//                try {
//                    byte[] response = mifare.transceive(command);
//                    versionResponse = toHex(response);
//                } catch (IOException e) {
//                    versionResponse = "Not supported or failed: "
//                            + e.getMessage();
//                }
//                String message =
//                                "Tag ID:\n" + toHex(tag.getId())
//                                + "\n\nPWD_AUTH:\n"
//                                + versionResponse;
//                showResult(message);
//
//            } catch (IOException e) {
//                showResult("NFC error: " + e.getMessage());
//            }
//            finally {
//                try {
//                    mifare.close();
//                } catch (IOException ignored) {
//                }
//            }
//        });

        // loaded ticket data
        // command format: "write" command code ("A2"), page address (one byte), data to write (four bytes)
        byte[][] commands = {
                { (byte) 0xA2, (byte) 0x04, (byte) 0x10 ,(byte) 0xA1, (byte) 0x53, (byte) 0x65 },
                { (byte) 0xA2, (byte) 0x05, (byte) 0xBE ,(byte) 0x88, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x06, (byte) 0x4B ,(byte) 0x80, (byte) 0x8B, (byte) 0x9F },
                { (byte) 0xA2, (byte) 0x07, (byte) 0x0E ,(byte) 0x19, (byte) 0xC2, (byte) 0x70 },
                { (byte) 0xA2, (byte) 0x08, (byte) 0x72 ,(byte) 0x51, (byte) 0x51, (byte) 0x6C },
                { (byte) 0xA2, (byte) 0x09, (byte) 0x4A ,(byte) 0x21, (byte) 0x90, (byte) 0x04 },
                { (byte) 0xA2, (byte) 0x0A, (byte) 0x61 ,(byte) 0x27, (byte) 0x07, (byte) 0x7B },
                { (byte) 0xA2, (byte) 0x0B, (byte) 0x00 ,(byte) 0xC0, (byte) 0x4B, (byte) 0x50 },
                { (byte) 0xA2, (byte) 0x0C, (byte) 0x84 ,(byte) 0x00, (byte) 0x00, (byte) 0x01 },
                { (byte) 0xA2, (byte) 0x0D, (byte) 0x03 ,(byte) 0xE9, (byte) 0x03, (byte) 0xF4 },
                { (byte) 0xA2, (byte) 0x0E, (byte) 0x42 ,(byte) 0xA6, (byte) 0x8B, (byte) 0x9F },
                { (byte) 0xA2, (byte) 0x0F, (byte) 0x00 ,(byte) 0x02, (byte) 0x25, (byte) 0x42 },
                { (byte) 0xA2, (byte) 0x10, (byte) 0x00 ,(byte) 0x98, (byte) 0x96, (byte) 0xC7 },
                { (byte) 0xA2, (byte) 0x11, (byte) 0x00 ,(byte) 0x09, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x12, (byte) 0x00 ,(byte) 0x00, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x13, (byte) 0x42 ,(byte) 0xA6, (byte) 0x83, (byte) 0xCE },
                { (byte) 0xA2, (byte) 0x14, (byte) 0xA6 ,(byte) 0x83, (byte) 0xCE, (byte) 0x54 },
                { (byte) 0xA2, (byte) 0x15, (byte) 0x6B ,(byte) 0x52, (byte) 0x4D, (byte) 0x03 },
                { (byte) 0xA2, (byte) 0x16, (byte) 0x86 ,(byte) 0x0E, (byte) 0x9F, (byte) 0xE3 },
                { (byte) 0xA2, (byte) 0x17, (byte) 0x57 ,(byte) 0x30, (byte) 0x51, (byte) 0xF5 },
                { (byte) 0xA2, (byte) 0x18, (byte) 0xA9 ,(byte) 0xAE, (byte) 0xE8, (byte) 0x60 },
                { (byte) 0xA2, (byte) 0x19, (byte) 0xE2 ,(byte) 0x64, (byte) 0xA9, (byte) 0xB5 },
                { (byte) 0xA2, (byte) 0x1A, (byte) 0xE7 ,(byte) 0xFC, (byte) 0x9B, (byte) 0xE3 },
                { (byte) 0xA2, (byte) 0x1B, (byte) 0x43 ,(byte) 0x36, (byte) 0x86, (byte) 0xA6 },
                { (byte) 0xA2, (byte) 0x1C, (byte) 0xE8 ,(byte) 0x6C, (byte) 0x7F, (byte) 0xED },
                { (byte) 0xA2, (byte) 0x1D, (byte) 0xE2 ,(byte) 0x64, (byte) 0xA9, (byte) 0xB5 },
                { (byte) 0xA2, (byte) 0x1E, (byte) 0xE7 ,(byte) 0xFC, (byte) 0x9B, (byte) 0xE3 },
                { (byte) 0xA2, (byte) 0x1F, (byte) 0x43 ,(byte) 0x36, (byte) 0x86, (byte) 0xA6 },
                { (byte) 0xA2, (byte) 0x20, (byte) 0xE8 ,(byte) 0x6C, (byte) 0x7F, (byte) 0xED },
                { (byte) 0xA2, (byte) 0x21, (byte) 0x19 ,(byte) 0x04, (byte) 0x00, (byte) 0xE6 },
                { (byte) 0xA2, (byte) 0x22, (byte) 0x42 ,(byte) 0xB0, (byte) 0x97, (byte) 0x08 },
                { (byte) 0xA2, (byte) 0x23, (byte) 0x01 ,(byte) 0xA1, (byte) 0x34, (byte) 0x01 }
        };

        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);

                byte[] PWD_AUTH = new byte[] { (byte) 0x1b, (byte) 0x60, (byte) 0x09, (byte) 0xad, (byte) 0xb6 };
                try {
                    mifare.transceive(PWD_AUTH);
                } catch (IOException e) {
                    e.getMessage();
                }

                for (int i = 0; i < 32; i++) {
                    String txt_response;
                    try {
                        byte[] response = mifare.transceive(commands[i]);
                        txt_response = toHex(response);
                    } catch (IOException e) {
                        txt_response = "Not supported or failed: "
                                + e.getMessage();
                    }

                    android.util.Log.d(
                            "NFC",
                            "Iteration " + i + " response: " + txt_response
                    );
                }

            } catch (IOException e) {
                showResult("NFC error: " + e.getMessage());
            } finally {
                try {
                    mifare.close();
                } catch (IOException ignored) {}
            }
        });


        notify("Ticket loaded");

    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }

    private void showResult(String message) {
        runOnUiThread(() -> txtResult.setText(message));
    }

    public void notify(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }
}
