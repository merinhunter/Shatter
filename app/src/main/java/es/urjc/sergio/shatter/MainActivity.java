package es.urjc.sergio.shatter;

import android.annotation.SuppressLint;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Objects;

import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;
import es.urjc.sergio.keystore.KeyStoreManager;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        System.out.println("CertPath: " + ExternalStorage.createDirs(FileIO.certificatesPath));
        System.out.println("SendPath: " + ExternalStorage.createDirs(FileIO.sendPath));

        if (!KeyStoreManager.existsAlias(KeyStoreManager.mainAlias)) {
            Log.d(TAG, "Main keys don't exist");
            try {
                KeyStoreManager.generateKeyPair(KeyStoreManager.mainAlias);
            } catch (Exception e) {
                Log.e(TAG, e.getMessage(), e);
                System.exit(-1);
            }

            Log.d(TAG, "Main keys created");
        }

        try {
            KeyStoreManager.importCertificate("public", "main.crt");
        } catch (IOException e) {
            e.printStackTrace();
        }

        refreshList();
    }

    public void deleteKey(final String alias) {
        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"" + alias + "\" from the keystore?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        KeyStoreManager.deleteEntry(alias);
                        refreshList();
                        dialog.dismiss();
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .create();
        alertDialog.show();
    }

    private void refreshKeys() {
        keyAliases = new ArrayList<>();

        Enumeration<String> aliases = KeyStoreManager.getAliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if(Objects.equals(alias, KeyStoreManager.mainAlias))
                continue;

            keyAliases.add(alias);
        }
    }

    @SuppressLint("InflateParams")
    private void refreshList() {
        refreshKeys();

        LinearLayout listLayout = findViewById(R.id.keyList);
        listLayout.removeAllViews();

        for (String alias : keyAliases) {
            Log.i(TAG, "Alias found: " + alias);
            RelativeLayout card = (RelativeLayout) getLayoutInflater().inflate(R.layout.card, null);
            fillCard(card, alias);
            listLayout.addView(card);
        }
    }

    private void fillCard(RelativeLayout card, String alias) {
        for (int i = 0; i < card.getChildCount(); i++) {
            View v = card.getChildAt(i);

            switch (v.getId()) {
                case R.id.keyAlias:
                    TextView text_view = (TextView) v;
                    text_view.setText(alias);
                    break;
                case R.id.deleteButton:
                    Button deleteButton = (Button) v;
                    deleteButton.setOnClickListener(new DeleteButton(alias));
                    break;
                case R.id.decryptButton:
                    Button decryptButton = (Button) v;
                    decryptButton.setOnClickListener(new DecryptButton(alias));
                    break;
                case R.id.encryptButton:
                    Button encryptButton = (Button) v;
                    encryptButton.setOnClickListener(new EncryptButton(alias));
                    break;
            }
        }
    }

    private class DeleteButton implements View.OnClickListener {
        String alias;

        private DeleteButton(String alias) {
            this.alias = alias;
        }

        @Override
        public void onClick(View button) {
            deleteKey(this.alias);
        }
    }

    private class DecryptButton implements View.OnClickListener {
        String alias;

        private DecryptButton(String alias) {
            this.alias = alias;
        }

        @Override
        public void onClick(View button) {
            EditText editText = findViewById(R.id.sessionText);
            String sessionID = editText.getText().toString();

            try {
                KeyStoreManager.exportCertificate(KeyStoreManager.mainAlias);
            } catch (IOException e) {
                e.printStackTrace();
            }

            int time = Toast.LENGTH_SHORT;
            Toast msg = Toast.makeText(MainActivity.this, alias + ' ' + sessionID, time);
            msg.show();
        }
    }

    private class EncryptButton implements View.OnClickListener {
        String alias;

        private EncryptButton(String alias) {
            this.alias = alias;
        }

        public void onClick(View Button) {
            EditText editText = findViewById(R.id.sessionText);
            String filePath = editText.getText().toString();

            SliceEncrypt.sliceEncrypt(filePath, this.alias, 10);

            int time = Toast.LENGTH_SHORT;
            Toast msg = Toast.makeText(MainActivity.this, alias + ' ' + filePath, time);
            msg.show();
        }
    }
}
