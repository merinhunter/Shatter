package es.urjc.sergio.importKey;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.util.Objects;

import es.urjc.sergio.common.FileUtils;
import es.urjc.sergio.keystore.KeyStoreHandler;
import es.urjc.sergio.shatter.MainActivity;
import es.urjc.sergio.shatter.R;

public class ImportKey extends AppCompatActivity {
    private static final String TAG = "ImportKey";
    private static final int REQUEST_CODE = 4836;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.import_key);

        Button selectButton = findViewById(R.id.selectButton);
        selectButton.setOnClickListener(new SelectButton());

        Button importDoneButton = findViewById(R.id.importDoneButton);
        importDoneButton.setOnClickListener(new ImportDoneButton());
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case REQUEST_CODE:
                if (resultCode == RESULT_OK) {
                    if (data != null) {
                        final Uri uri = data.getData();
                        Log.i(TAG, "Uri = " + uri.getPath());
                        try {
                            final String path = FileUtils.getPath(this, uri);

                            EditText editText = findViewById(R.id.crtFile);
                            editText.setText(path, TextView.BufferType.EDITABLE);

                            if (path != null)
                                showMessage("File selected: " + path);
                            else
                                showMessage("Invalid certificate");
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                break;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private void showChooser() {
        Intent chooseFile = new Intent(Intent.ACTION_GET_CONTENT);

        Uri uri = Uri.parse(Environment.getExternalStorageDirectory().getPath()
                + File.separator + "Shatter/certs" + File.separator);

        chooseFile.setDataAndType(uri, "*/*");
        chooseFile = Intent.createChooser(chooseFile, "Choose a file");

        startActivityForResult(chooseFile, REQUEST_CODE);
    }

    private void showMessage(String m) {
        int time = Toast.LENGTH_SHORT;
        Toast msg = Toast.makeText(ImportKey.this, m, time);
        msg.show();
    }

    private void openMainActivity() {
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }

    private class SelectButton implements View.OnClickListener {
        public void onClick(View Button) {
            Log.d(TAG, "Pressed selection button");
            showChooser();
        }
    }

    private class ImportDoneButton implements View.OnClickListener {
        public void onClick(View Button) {
            Log.d(TAG, "Pressed import done button");
            String alias = ((EditText) findViewById(R.id.keyAlias_import)).getText().toString();
            String certPath = ((EditText) findViewById(R.id.crtFile)).getText().toString();

            if (Objects.equals(alias, "")) {
                Log.d(TAG, "Alias is empty");
                showMessage("You haven't chosen any alias");
            } else {
                if (KeyStoreHandler.existsAlias(alias)) {
                    showMessage("Alias " + alias + " already exists");
                    return;
                }

                if (Objects.equals(certPath, "")) {
                    showMessage("You haven't chosen any cert file");
                    return;
                }

                try {
                    KeyStoreHandler.importCertificate(alias, certPath);
                } catch (IOException e) {
                    Log.e(TAG, "Some errors occurred during the import");
                    return;
                }

                Log.d(TAG, alias + " imported");
                showMessage(alias + " imported");

                openMainActivity();
            }
        }
    }
}
