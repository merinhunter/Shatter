package es.urjc.sergio.shatter;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.LinearLayout;

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Enumeration;

import es.urjc.sergio.keystore.KeyStoreManager;

public class MainActivity extends AppCompatActivity {
    private KeyStoreManager ksManager;
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        ksManager = new KeyStoreManager();
        try {
            System.out.println(ksManager.getKeyStore().containsAlias(ksManager.mainAlias));
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        fillList();
    }

    private void refreshKeys() {
        keyAliases = new ArrayList<>();

        try {
            Enumeration<String> aliases = ksManager.getKeyStore().aliases();
            while(aliases.hasMoreElements())
                keyAliases.add(aliases.nextElement());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private void fillList() {
        refreshKeys();
        LinearLayout layout = (LinearLayout) findViewById(R.id.keyList);

        for(String alias : keyAliases) {
            // TODO: Fill card data for each alias
            layout.addView(null);
        }
    }
}
