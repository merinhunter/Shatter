package es.urjc.sergio.shatter;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.ListView;
import android.widget.RelativeLayout;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {
    private KeyStore ks;
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.header);

        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            System.out.println(ks.containsAlias("main"));
        } catch (Exception e) {
            e.printStackTrace();
        }

        RelativeLayout rl = findViewById(R.id.header);
        ListView listView = (ListView) View.inflate(this, R.layout.key_list, null);
        rl.addView(listView);

        //ListView listView = findViewById(R.id.keyList);
        //View listHeader = View.inflate(this, R.layout.header, null);
        //listView.addHeaderView(listHeader);
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
