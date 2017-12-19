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
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;

import javax.net.ssl.KeyManager;

import es.urjc.sergio.keystore.KeyStoreManager;
import es.urjc.sergio.rsa.RSALibrary;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private KeyStoreManager ksManager;
    private ArrayList<String> keyAliases;
    //private final String keyStoreName = "myKeyStore";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        //File f = new File(keyStoreName);
        //System.out.println(f.exists());

        ksManager = new KeyStoreManager();

        if(!KeyStoreManager.existsAlias(KeyStoreManager.mainAlias)) {
            System.out.println("Main keys don't exist");
            try {
                KeyStoreManager.generateKeyPair(KeyStoreManager.mainAlias);
            } catch (Exception e) {
                System.err.println("Error creating the keys");
                e.printStackTrace();
            }
            /*RSALibrary rsa = new RSALibrary();
            try {
                KeyPair keyPair = rsa.generateKeys();
                ksManager.savePrivateKey(ksManager.mainAlias, keyPair.getPrivate(), keyPair.getPublic());
            } catch (Exception e) {
                System.err.println("Error creating the main key pair: " + e.getMessage());
                e.printStackTrace();
                System.exit(-1);
            }*/
            System.out.println("Main keys created");
        }

        //ksManager.saveKeyStore();

        /*RSALibrary rsa = new RSALibrary();
        try {
            KeyPair keyPair = rsa.generateKeys();
            ksManager.savePrivateKey("main", keyPair.getPrivate(), keyPair.getPublic());
        } catch (Exception e) {
            System.err.println("Exception: " + e.getMessage());
            e.printStackTrace();
        }*/

        refreshList();

        /*try {
            Key privateKey = ksManager.getPrivateKey(ksManager.mainAlias);
            PublicKey publicKey = ksManager.getPublicKey(ksManager.mainAlias);

            System.out.println("PUBLIC 2: " + publicKey.getEncoded().length);
            System.out.println("PRIVATE 2: " + Arrays.toString(privateKey.getEncoded()));
        } catch (Exception e) {
            System.err.println("Exception: " + e.getMessage());
            System.exit(-1);
        }*/

        /*try {
            PrivateKey privateKey = (PrivateKey) RSALibrary.getKey(RSALibrary.PRIVATE_KEY_FILE);
            System.out.println(Arrays.toString(Hex.decode(privateKey.getEncoded())));
        } catch (Exception e) {
            e.printStackTrace();
        }*/

        System.out.println("DONE");
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

    private class SelectButton implements View.OnClickListener {
        String alias;

        private SelectButton(String alias) {
            this.alias = alias;
        }

        @Override
        public void onClick(View button) {
            EditText sessionText = findViewById(R.id.sessionText);
            String sessionID = sessionText.getText().toString();
            String text = null;

            try {
                //PrivateKey privateKey = ksManager.getPrivateKey(this.alias);
                //PublicKey publicKey = ksManager.getPublicKey(this.alias);

                //byte[] cipherText = RSALibrary.encrypt(sessionID.getBytes(), publicKey);
                //byte[] plaintext = RSALibrary.decrypt(cipherText, privateKey);

                /*if (cipherText != null) {
                    text = Arrays.toString(cipherText);
                }*/
                //text = Hex.toHexString(ksManager.sign(this.alias, sessionID.getBytes()));
                byte[] cipherText = KeyStoreManager.encrypt(this.alias, sessionID.getBytes());
                text = new String(KeyStoreManager.decrypt(this.alias, cipherText));
            } catch (Exception e) {
                e.printStackTrace();
            }

            int time = Toast.LENGTH_SHORT;
            Toast msg = Toast.makeText(MainActivity.this, text, time);
            msg.show();
        }
    }

    public void deleteKey(final String alias) {
        AlertDialog alertDialog =new AlertDialog.Builder(this)
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

            //if(Objects.equals(alias, ksManager.mainAlias))
            //    continue;

            keyAliases.add(alias);
        }
    }

    @SuppressLint("InflateParams")
    private void refreshList() {
        refreshKeys();

        LinearLayout listLayout = findViewById(R.id.keyList);
        listLayout.removeAllViews();

        for (String alias : keyAliases) {
            System.out.println("Alias found: " + alias);
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
                    Button delete_button = (Button) v;
                    delete_button.setOnClickListener(new DeleteButton(alias));
                    break;
                case R.id.selectButton:
                    Button select_button = (Button) v;
                    select_button.setOnClickListener(new SelectButton(alias));
                    break;
            }
        }
    }
}
