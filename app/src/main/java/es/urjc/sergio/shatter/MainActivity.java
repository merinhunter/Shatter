package es.urjc.sergio.shatter;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.ListView;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;

import es.urjc.sergio.keystore.KeyStoreManager;

public class MainActivity extends AppCompatActivity {
    private KeyStore ks;
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ListView listView = (ListView) View.inflate(this, R.layout.key_list,null);
        View listHeader = View.inflate(this, R.layout.header, null);
        listView.addHeaderView(listHeader);

        setContentView(listView);
    }

    private void refreshKeys() {
        keyAliases = new ArrayList<>();

        try {
            Enumeration<String> aliases = ks.aliases();
            while(aliases.hasMoreElements())
                keyAliases.add(aliases.nextElement());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        /*if(listAdapter != null)
            listAdapter.notifyDataSetChanged();*/
    }
}
