package com.example.athenaticket;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    byte PWD_AUTH_COMMAND_CODE_HEX = 0x1b;
    byte[] PWD = { (byte) 0x36, (byte) 0x8E, (byte) 0x3A, (byte) 0x24 };
    byte[][] COMMANDS_TO_WRITE_VERSION_MIFARE_ULTRALIGHT_EV1_128_BYTES = {
            { (byte) 0xa2, (byte) 0xfa, (byte) 0x00, (byte) 0x04, (byte) 0x03, (byte) 0x01, },
            { (byte) 0xa2, (byte) 0xfb, (byte) 0x01, (byte) 0x00, (byte) 0x0e, (byte) 0x03, },
            { (byte) 0xa2, (byte) 0xfc, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, },
    };
    byte[] READ_SIG_COMMAND_HEX_CODE = { (byte) 0x3c, (byte) 0x00 };
    byte[] SIGNATURE = { (byte) 0x8B, (byte) 0xAA, (byte) 0x16, (byte) 0x3E, (byte) 0x22, (byte) 0xB8,
            (byte) 0x7A, (byte) 0x9B, (byte) 0x2E, (byte) 0x1F, (byte) 0xA2, (byte) 0x75, (byte) 0xB4,
            (byte) 0x32, (byte) 0x9C, (byte) 0xC8, (byte) 0x47, (byte) 0x45, (byte) 0x35, (byte) 0xA3,
            (byte) 0x5F, (byte) 0xC6, (byte) 0x34, (byte) 0x50, (byte) 0xBB, (byte) 0x06, (byte) 0x22,
            (byte) 0xCC, (byte) 0x32, (byte) 0x2F, (byte) 0x7F, (byte) 0x08
    };

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
            txtResult.setText(R.string.nfc_is_not_supported);
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
            txtResult.setText(R.string.enable_nfc_in_settings);
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

        byte[] uid = tag.getId();
        StringBuilder hex = new StringBuilder();
        for (byte b : uid) {
            hex.append(String.format("%02X ", b & 0xFF));
        }
//        notify(hex.toString().trim());

        // magic card does not get recognized as ultralight
//        MifareUltralight mifare = MifareUltralight.get(tag);
//        if (mifare == null) {
//            notify("Not recognized as MIFARE Ultralight.");
//            return;
//        }
        NfcA mifare = NfcA.get(tag);
        if (mifare == null) {
            notify("Not recognized as NfcA tag.");
            return;
        }

        // command format: "write" command code ("A2"), page address (one byte), data to write (four bytes)
        byte[][] commands = {
                { (byte) 0xA2, (byte) 0x00 , (byte) 0x04, (byte) 0xEC, (byte) 0x91, (byte) 0xF1 },
                { (byte) 0xA2, (byte) 0x01 , (byte) 0x82, (byte) 0xB7, (byte) 0x25, (byte) 0x90 },
                { (byte) 0xA2, (byte) 0x02 , (byte) 0x80, (byte) 0x48, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x03 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x04 , (byte) 0x10, (byte) 0xA1, (byte) 0x4E, (byte) 0x67 },
                { (byte) 0xA2, (byte) 0x05 , (byte) 0xD9, (byte) 0x3F, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x06 , (byte) 0x4B, (byte) 0x81, (byte) 0x19, (byte) 0x3A },
                { (byte) 0xA2, (byte) 0x07 , (byte) 0xAF, (byte) 0x63, (byte) 0xD7, (byte) 0xD6 },
                { (byte) 0xA2, (byte) 0x08 , (byte) 0x83, (byte) 0x61, (byte) 0x5E, (byte) 0xC1 },
                { (byte) 0xA2, (byte) 0x09 , (byte) 0x31, (byte) 0xB3, (byte) 0x17, (byte) 0x0F },
                { (byte) 0xA2, (byte) 0x0A , (byte) 0x2E, (byte) 0xE3, (byte) 0x88, (byte) 0xDC },
                { (byte) 0xA2, (byte) 0x0B , (byte) 0x01, (byte) 0xC0, (byte) 0x4B, (byte) 0x50 },
                { (byte) 0xA2, (byte) 0x0C , (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x01 },
                { (byte) 0xA2, (byte) 0x0D , (byte) 0x03, (byte) 0xEA, (byte) 0x04, (byte) 0x11 },
                { (byte) 0xA2, (byte) 0x0E , (byte) 0x42, (byte) 0xB9, (byte) 0x19, (byte) 0x3A },
                { (byte) 0xA2, (byte) 0x0F , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x42 },
                { (byte) 0xA2, (byte) 0x10 , (byte) 0x00, (byte) 0x98, (byte) 0x98, (byte) 0x81 },
                { (byte) 0xA2, (byte) 0x11 , (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x12 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x13 , (byte) 0x42, (byte) 0xB9, (byte) 0x19, (byte) 0x31 },
                { (byte) 0xA2, (byte) 0x14 , (byte) 0xB9, (byte) 0x19, (byte) 0x31, (byte) 0xF3 },
                { (byte) 0xA2, (byte) 0x15 , (byte) 0xDA, (byte) 0xD5, (byte) 0x89, (byte) 0xFB },
                { (byte) 0xA2, (byte) 0x16 , (byte) 0xF5, (byte) 0x74, (byte) 0x54, (byte) 0x8F },
                { (byte) 0xA2, (byte) 0x17 , (byte) 0x62, (byte) 0xEE, (byte) 0x70, (byte) 0x26 },
                { (byte) 0xA2, (byte) 0x18 , (byte) 0xB9, (byte) 0x89, (byte) 0x37, (byte) 0xF4 },
                { (byte) 0xA2, (byte) 0x19 , (byte) 0x04, (byte) 0xBE, (byte) 0x8D, (byte) 0x01 },
                { (byte) 0xA2, (byte) 0x1A , (byte) 0xD7, (byte) 0x2E, (byte) 0x01, (byte) 0xD6 },
                { (byte) 0xA2, (byte) 0x1B , (byte) 0xA0, (byte) 0xBB, (byte) 0xE0, (byte) 0x3E },
                { (byte) 0xA2, (byte) 0x1C , (byte) 0x0C, (byte) 0x49, (byte) 0x26, (byte) 0xD8 },
                { (byte) 0xA2, (byte) 0x1D , (byte) 0x04, (byte) 0xBE, (byte) 0x8D, (byte) 0x01 },
                { (byte) 0xA2, (byte) 0x1E , (byte) 0xD7, (byte) 0x2E, (byte) 0x01, (byte) 0xD6 },
                { (byte) 0xA2, (byte) 0x1F , (byte) 0xA0, (byte) 0xBB, (byte) 0xE0, (byte) 0x3E },
                { (byte) 0xA2, (byte) 0x20 , (byte) 0x0C, (byte) 0x49, (byte) 0x26, (byte) 0xD8 },
                { (byte) 0xA2, (byte) 0x21 , (byte) 0x0B, (byte) 0x04, (byte) 0x00, (byte) 0x78 },
                { (byte) 0xA2, (byte) 0x22 , (byte) 0x42, (byte) 0xBA, (byte) 0x88, (byte) 0x14 },
                { (byte) 0xA2, (byte) 0x23 , (byte) 0x01, (byte) 0xA1, (byte) 0x46, (byte) 0x01 },
                { (byte) 0xA2, (byte) 0x24 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xBD },
                { (byte) 0xA2, (byte) 0x25 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04 },
                { (byte) 0xA2, (byte) 0x26 , (byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x27 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 },
                { (byte) 0xA2, (byte) 0x28 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 },
        };

//        read_signature(mifare);

//        write_version_mifare_ultralight_ev1_128_bytes(mifare);
//        write_signature(mifare, SIGNATURE);
//        write_pwd(mifare, PWD);
//        write_visible_pages(mifare, PWD, commands);
    }

    private void write_visible_pages(NfcA mifare, byte[] PWD, byte[][] commands) {
        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);
                String txt_response;

                // authentication
                byte[] PWD_AUTH = new byte[] {PWD_AUTH_COMMAND_CODE_HEX, PWD[0], PWD[1], PWD[2], PWD[3] };
                try {
                    mifare.transceive(PWD_AUTH);
                } catch (Exception e){
                    e.getMessage();
                    txtResult.setText(R.string.ticket_authentication_failed);
                    return;
                }

                // write
                for (byte[] command : commands) {
                    try {
                        byte[] response = mifare.transceive(command);
                        txt_response = toHex(response);
                        txtResult.setText(txt_response);
                    } catch (IOException e) {
                        txt_response = "Not supported or failed: " + e.getMessage();
                        txtResult.setText(txt_response);
                    }
                }

            } catch (IOException e) {
                showResult("NFC error: " + e.getMessage());
            } finally {
                try {
                    mifare.close();
                } catch (IOException ignored) {}
            }
        });

    }

    private void write_version_mifare_ultralight_ev1_128_bytes(NfcA mifare) {
        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);
                String txt_response;
                for (byte[] command : COMMANDS_TO_WRITE_VERSION_MIFARE_ULTRALIGHT_EV1_128_BYTES) {
                    try {
                        byte[] response = mifare.transceive(command);
                        txt_response = toHex(response);
                        txtResult.setText(txt_response);
                    } catch (IOException e) {
                        txt_response = "Not supported or failed: " + e.getMessage();
                        txtResult.setText(txt_response);
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    mifare.close();
                } catch (IOException ignored) {}
            }
        });
    }

    private void read_signature(NfcA mifare) {
        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);
                String txt_response;
                try {
                    byte[] response = mifare.transceive(READ_SIG_COMMAND_HEX_CODE);
                    txt_response = toHex(response);
                    Log.d("CARD SIGNATURE", txt_response);
                } catch (IOException e) {
                    txt_response = "Not supported or failed: " + e.getMessage();
                    Log.d("ERROR WHILE TRYING TO READ SIGNATURE", txt_response);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    mifare.close();
                } catch (IOException ignored) {}
            }
        });
    }

    private void write_signature(NfcA mifare, byte[] signature) {
        byte[][] commands = {
                { (byte) 0xa2, (byte) 0xf2, signature[0], signature[1], signature[2], signature[3] },
                { (byte) 0xa2, (byte) 0xf3, signature[4], signature[5], signature[6], signature[7] },
                { (byte) 0xa2, (byte) 0xf4, signature[8], signature[9], signature[10], signature[11] },
                { (byte) 0xa2, (byte) 0xf5, signature[12], signature[13], signature[14], signature[15] },
                { (byte) 0xa2, (byte) 0xf6, signature[16], signature[17], signature[18], signature[19] },
                { (byte) 0xa2, (byte) 0xf7, signature[20], signature[21], signature[22], signature[23] },
                { (byte) 0xa2, (byte) 0xf8, signature[24], signature[25], signature[26], signature[27] },
                { (byte) 0xa2, (byte) 0xf9, signature[28], signature[29], signature[30], signature[31] },
        };
        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);
                String txt_response;
                for (byte[] command : commands) {
                    try {
                        byte[] response = mifare.transceive(command);
                        txt_response = toHex(response);
                        txtResult.setText(txt_response);
                        Log.d("CARD SIGNATURE WRITTEN", txt_response);
                    } catch (IOException e) {
                        txt_response = "Not supported or failed: " + e.getMessage();
                        txtResult.setText(txt_response);
                        Log.d("CARD SIGNATURE NOT WRITTEN", txt_response);
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    mifare.close();
                } catch (IOException ignored) {}
            }
        });
    }

    private void write_pwd(NfcA mifare, byte[] pwd) {
        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);
                String txt_response;
                try {
                    byte[] response = mifare.transceive(new byte[] { (byte) 0xa2, (byte) 0xf0, pwd[0], pwd[1], pwd[2], pwd[3] });
                    txt_response = toHex(response);
                    Log.d("PWD WRITTEN", txt_response);
                } catch (IOException e) {
                    txt_response = "Not supported or failed: " + e.getMessage();
                    Log.d("ERROR WHILE TRYING TO WRITE PWD", txt_response);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    mifare.close();
                } catch (IOException ignored) {}
            }
        });
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
