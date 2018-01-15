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

import java.io.File;
import java.util.ArrayList;
import java.util.Enumeration;

import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;
import es.urjc.sergio.http.HTTPClient;
import es.urjc.sergio.keystore.KeyStoreHandler;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        System.out.println("CertPath: " + ExternalStorage.createDirs(FileIO.certificatesPath));
        System.out.println("SendPath: " + ExternalStorage.createDirs(FileIO.sendPath));

        if (!KeyStoreHandler.existsAlias(KeyStoreHandler.mainAlias)) {
            Log.d(TAG, "Main keys don't exist");
            try {
                KeyStoreHandler.generateKeyPair(KeyStoreHandler.mainAlias);
            } catch (Exception e) {
                Log.e(TAG, e.getMessage(), e);
                System.exit(-1);
            }

            Log.d(TAG, "Main keys created");
        }

        refreshList();
    }

    public void deleteKey(final String alias) {
        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"" + alias + "\" from the keystore?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        KeyStoreHandler.deleteEntry(alias);
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

    public boolean confirmDialog() {
        final boolean[] result = {false};
        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Confirm Dialog")
                .setMessage("Some files have not been downloaded, do you want to continue anyway?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        result[0] = true;
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
        return result[0];
    }

    private void refreshKeys() {
        keyAliases = new ArrayList<>();

        Enumeration<String> aliases = KeyStoreHandler.getAliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            // TODO: Remove
            /*if(Objects.equals(alias, KeyStoreHandler.mainAlias))
                continue;*/

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

            String sessionPath = ExternalStorage.getFilePath(FileIO.appPath + sessionID + '/');
            FileIO.makeDirectory(sessionPath);

            HTTPClient client = new HTTPClient();
            try {
                client.getIndex(sessionID);
            } catch (Exception e) {
                e.printStackTrace();
            }

            String indexPath = sessionPath + FileIO.indexFile;

            ArrayList<String> urls = FileIO.readIndex(indexPath);

            if (urls.isEmpty()) {
                int time = Toast.LENGTH_SHORT;
                Toast msg = Toast.makeText(MainActivity.this, "There are no files to download", time);
                msg.show();
                return;
            }

            String tmpPath = sessionPath + FileIO.decomposedPath;
            FileIO.makeDirectory(tmpPath);

            String errorsFile = sessionPath + FileIO.errorsFile;

            for (String url : urls) {
                try {
                    client.getFile(url, tmpPath);
                } catch (Exception e) {
                    FileIO.append(errorsFile, "Missing " + url);
                    e.printStackTrace();
                }
            }

            if (new File(errorsFile).exists()) {
                if (confirmDialog()) {
                    DecryptCompose.decryptCompose(sessionID, this.alias);
                }
            } else {
                DecryptCompose.decryptCompose(sessionID, this.alias);
            }

            int time = Toast.LENGTH_SHORT;
            Toast msg = Toast.makeText(MainActivity.this, "Decrypt & Compose done", time);
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
            Toast msg = Toast.makeText(MainActivity.this, "Slice & Encrypt done", time);
            msg.show();
        }
    }
}
