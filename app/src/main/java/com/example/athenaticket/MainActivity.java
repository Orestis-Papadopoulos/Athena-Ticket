package com.example.athenaticket;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.util.Log;
import android.view.WindowManager;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    byte[] SECTOR_SELECT = { (byte) 0xc2, (byte) 0xff };
    byte SECTOR_ONE = (byte) 0x01;
    byte PWD_AUTH_COMMAND_CODE_HEX = (byte) 0x1b;
    byte[] PWD = { (byte) 0x36, (byte) 0x8E, (byte) 0x3A, (byte) 0x24 };
    byte WRITE_COMMAND_CODE_HEX = (byte) 0xa2;

    // for magic card: you need to write the version, signature, password

    // same for all tickets
    byte[][] COMMANDS_TO_WRITE_VERSION_MIFARE_ULTRALIGHT_EV1_128_BYTES = {
            { WRITE_COMMAND_CODE_HEX, (byte) 0xfa, (byte) 0x00, (byte) 0x04, (byte) 0x03, (byte) 0x01, },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xfb, (byte) 0x01, (byte) 0x00, (byte) 0x0e, (byte) 0x03, },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xfc, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, },
    };
    byte[][] READ_SIG_COMMAND_HEX_CODE = {{ (byte) 0x3c, (byte) 0x00 }};
    byte[][] COMMAND_TO_WRITE_PWD = {{ WRITE_COMMAND_CODE_HEX, (byte) 0xf0, PWD[0], PWD[1], PWD[2], PWD[3] }};

    // specific for each ticket
    byte[] SIGNATURE = { (byte) 0x8B, (byte) 0xAA, (byte) 0x16, (byte) 0x3E, (byte) 0x22, (byte) 0xB8,
            (byte) 0x7A, (byte) 0x9B, (byte) 0x2E, (byte) 0x1F, (byte) 0xA2, (byte) 0x75, (byte) 0xB4,
            (byte) 0x32, (byte) 0x9C, (byte) 0xC8, (byte) 0x47, (byte) 0x45, (byte) 0x35, (byte) 0xA3,
            (byte) 0x5F, (byte) 0xC6, (byte) 0x34, (byte) 0x50, (byte) 0xBB, (byte) 0x06, (byte) 0x22,
            (byte) 0xCC, (byte) 0x32, (byte) 0x2F, (byte) 0x7F, (byte) 0x08
    };

    byte[][] COMMANDS_TO_WRITE_SIGNATURE = {
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf2, SIGNATURE[0], SIGNATURE[1], SIGNATURE[2], SIGNATURE[3] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf3, SIGNATURE[4], SIGNATURE[5], SIGNATURE[6], SIGNATURE[7] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf4, SIGNATURE[8], SIGNATURE[9], SIGNATURE[10], SIGNATURE[11] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf5, SIGNATURE[12], SIGNATURE[13], SIGNATURE[14], SIGNATURE[15] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf6, SIGNATURE[16], SIGNATURE[17], SIGNATURE[18], SIGNATURE[19] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf7, SIGNATURE[20], SIGNATURE[21], SIGNATURE[22], SIGNATURE[23] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf8, SIGNATURE[24], SIGNATURE[25], SIGNATURE[26], SIGNATURE[27] },
            { WRITE_COMMAND_CODE_HEX, (byte) 0xf9, SIGNATURE[28], SIGNATURE[29], SIGNATURE[30], SIGNATURE[31] },
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

        // Prevent the screen from turning off, which immediately cuts NFC power
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

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
        for (byte b : uid) hex.append(String.format("%02X ", b & 0xFF));
        Log.d("Tag serial number", hex.toString());

        NfcA mifare = NfcA.get(tag);
        if (mifare == null) {
            notify("Not recognized as NfcA tag.");
            return;
        }

        // command format: "write" command code ("A2"), page address (one byte), data to write (four bytes)
        byte[][] commands_to_write_data_pages = {
                { PWD_AUTH_COMMAND_CODE_HEX, PWD[0], PWD[1], PWD[2], PWD[3] },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x04 , (byte) 0x10, (byte) 0xA1, (byte) 0x4E, (byte) 0x65 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x05 , (byte) 0x03, (byte) 0x0E, (byte) 0x00, (byte) 0x00 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x06 , (byte) 0x4B, (byte) 0x80, (byte) 0xE5, (byte) 0xD3 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x07 , (byte) 0x0A, (byte) 0x74, (byte) 0xB5, (byte) 0x4B },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x08 , (byte) 0x7A, (byte) 0x9C, (byte) 0xAD, (byte) 0x73 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x09 , (byte) 0x25, (byte) 0x2C, (byte) 0xD4, (byte) 0x26 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x0A , (byte) 0xB6, (byte) 0xEB, (byte) 0x1B, (byte) 0xD4 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x0B , (byte) 0x01, (byte) 0xC0, (byte) 0x4B, (byte) 0x50 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x0C , (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x01 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x0D , (byte) 0x03, (byte) 0xEA, (byte) 0x04, (byte) 0x11 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x0E , (byte) 0x42, (byte) 0xA0, (byte) 0xE5, (byte) 0xD3 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x0F , (byte) 0x00, (byte) 0x01, (byte) 0x58, (byte) 0x42 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x10 , (byte) 0x00, (byte) 0x98, (byte) 0x98, (byte) 0x81 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x11 , (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x00 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x12 , (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x13 , (byte) 0x42, (byte) 0xA0, (byte) 0xDD, (byte) 0xD3 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x14 , (byte) 0xA0, (byte) 0xDD, (byte) 0xD3, (byte) 0xA6 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x15 , (byte) 0xE3, (byte) 0x5E, (byte) 0x4F, (byte) 0x93 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x16 , (byte) 0x05, (byte) 0x60, (byte) 0xEF, (byte) 0x4D },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x17 , (byte) 0xC7, (byte) 0x13, (byte) 0xDF, (byte) 0x82 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x18 , (byte) 0x18, (byte) 0x6D, (byte) 0x48, (byte) 0xF1 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x19 , (byte) 0x6F, (byte) 0x89, (byte) 0xE6, (byte) 0x6A },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x1A , (byte) 0xE1, (byte) 0x55, (byte) 0x88, (byte) 0x12 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x1B , (byte) 0xB2, (byte) 0x40, (byte) 0x36, (byte) 0x91 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x1C , (byte) 0x56, (byte) 0x97, (byte) 0x31, (byte) 0x60 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x1D , (byte) 0x6F, (byte) 0x89, (byte) 0xE6, (byte) 0x6A },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x1E , (byte) 0xE1, (byte) 0x55, (byte) 0x88, (byte) 0x12 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x1F , (byte) 0xB2, (byte) 0x40, (byte) 0x36, (byte) 0x91 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x20 , (byte) 0x56, (byte) 0x97, (byte) 0x31, (byte) 0x60 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x21 , (byte) 0x19, (byte) 0x04, (byte) 0x00, (byte) 0xE6 },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x22 , (byte) 0x42, (byte) 0xA2, (byte) 0x96, (byte) 0x0B },
                { WRITE_COMMAND_CODE_HEX, (byte) 0x23 , (byte) 0x01, (byte) 0xA1, (byte) 0x34, (byte) 0x01 }
        };

        // you can:
        // 1. read a ticket's signature
        // 2. write a magic card's signature
        // 3. write the password
        // 4. write the version of a magic card
        // 5. write to data pages (for ticket) or to the whole memory (for magic card)
        execute_commands(mifare, commands_to_write_data_pages);
    }

    private void execute_commands(NfcA mifare, byte[][] commands) {
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

    // to determine in which address the counter value is stored
    private void write_address_value_to_page(NfcA mifare){
        executor.execute(() -> {
            try {
                mifare.connect();
                mifare.setTimeout(5000);
                String txt_response;
                for (int i = 0; i < 256; i++) {
                    try {
                        byte address = (byte) ((byte) i & 0xff); // make it unsigned
                        byte[] command = { (byte) 0xa2, address, address, address, address, address};
                        byte[] response = mifare.transceive(command);
                        txt_response = toHex(response);
                        txtResult.setText(txt_response);
                        Log.d("WRITING ADDRESS", txt_response);
                    } catch (IOException e) {
                        txt_response = "Not supported or failed: " + e.getMessage();
                        txtResult.setText(txt_response);
                        Log.d("COULD NOT WRITE ADDRESS", txt_response);
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
