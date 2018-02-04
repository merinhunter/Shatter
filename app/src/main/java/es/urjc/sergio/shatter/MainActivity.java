package es.urjc.sergio.shatter;

import android.annotation.SuppressLint;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;

import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;
import es.urjc.sergio.common.FileUtils;
import es.urjc.sergio.http.HTTPClient;
import es.urjc.sergio.importKey.ImportKey;
import es.urjc.sergio.keystore.KeyStoreHandler;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private static final int REQUEST_CODE = 6384;
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        Button selectButton = findViewById(R.id.selectButton);
        selectButton.setOnClickListener(new SelectButton());

        FloatingActionButton importButton = findViewById(R.id.importButton);
        importButton.setOnClickListener(new ImportButton());

        if (ExternalStorage.createDirs(FileIO.certificatesPath))
            Log.d(TAG, "CertPath created");

        if (ExternalStorage.createDirs(FileIO.sendPath))
            Log.d(TAG, "SendPath created");

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

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case REQUEST_CODE:
                if (resultCode == RESULT_OK) {
                    if (data != null) {
                        final Uri uri = data.getData();
                        Log.i(TAG, "Uri = " + uri.getEncodedPath());
                        try {
                            final String path = FileUtils.getPath(this, uri);
                            System.out.println(uri.getScheme());

                            EditText editText = findViewById(R.id.sessionText);
                            editText.setText(path, TextView.BufferType.EDITABLE);

                            Toast.makeText(MainActivity.this,
                                    "File selected: " + path, Toast.LENGTH_LONG).show();
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                break;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.conf, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.exportKey:
                confirmExport();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
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

    public void confirmExport() {
        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Confirm Export")
                .setMessage("You are going to export your main public key, do you want to continue?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        try {
                            KeyStoreHandler.exportCertificate(KeyStoreHandler.mainAlias);
                        } catch (IOException e) {
                            Log.e(TAG, e.getMessage());
                            showMessage("Some errors occurred during the export");
                        }
                        showMessage("Main key successfully exported");
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

    public void confirmDecrypt(final String sessionID, final String alias) {
        AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Confirm Decrypt")
                .setMessage("Some files have not been downloaded, do you want to continue anyway?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        DecryptCompose.decryptCompose(sessionID, alias);
                        showMessage("Decrypt & Compose done");
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

        Enumeration<String> aliases = KeyStoreHandler.getAliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            Log.d(TAG, "Alias found: " + alias);

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
            RelativeLayout card = (RelativeLayout) getLayoutInflater().inflate(R.layout.card, null);
            fillCard(card, alias);
            listLayout.addView(card);
        }
    }

    private void showMessage(String m) {
        int time = Toast.LENGTH_SHORT;
        Toast msg = Toast.makeText(MainActivity.this, m, time);
        msg.show();
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

    private void showChooser() {
        Intent chooseFile = new Intent(Intent.ACTION_GET_CONTENT);
        Uri uri = Uri.parse(Environment.getExternalStorageDirectory().getPath()
                + File.separator + "Shatter/certs" + File.separator);
        chooseFile.setDataAndType(uri, "*/*");
        //chooseFile.setType("*/*");
        //chooseFile.addCategory(Intent.CATEGORY_OPENABLE);
        chooseFile = Intent.createChooser(chooseFile, "Choose a file");
        startActivityForResult(chooseFile, REQUEST_CODE);
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

            Log.d(TAG, "Decrypt " + sessionID + " with alias " + this.alias);

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
                showMessage("There are no files to download");
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
                confirmDecrypt(sessionID, this.alias);
            } else {
                DecryptCompose.decryptCompose(sessionID, this.alias);
                showMessage("Decrypt & Compose done");
            }
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

            Log.d(TAG, "Encrypt " + filePath + " with alias " + this.alias);

            File file = null;
            try {
                file = new File(new URI(filePath));
            } catch (URISyntaxException e) {
                Log.e(TAG, e.getMessage());
            }
            System.out.println(file.exists());

            //SliceEncrypt.sliceEncrypt(filePath, this.alias, 200000);

            showMessage("Slice & Encrypt done");
        }
    }

    private class SelectButton implements View.OnClickListener {
        public void onClick(View Button) {
            Log.d(TAG, "Pressed selection button");
            showChooser();
        }
    }

    private void openImportActivity() {
        Intent intent = new Intent(this, ImportKey.class);
        startActivity(intent);
    }

    private class ImportButton implements View.OnClickListener {
        public void onClick(View Button) {
            Log.d(TAG, "Pressed import button");
            openImportActivity();
        }
    }
}
