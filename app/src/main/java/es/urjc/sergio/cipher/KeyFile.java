package es.urjc.sergio.cipher;

import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import java.security.PrivateKey;

import es.urjc.sergio.keystore.KeyStoreHandler;
import es.urjc.sergio.rsa.RSALibrary;
import es.urjc.sergio.rsa.Signature;

public class KeyFile {
    private byte[] key;
    private Signature signature;

    public KeyFile(byte[] key) {
        this.key = key;
    }

    public KeyFile(EncKeyFile encKeyFile) throws Exception {
        //PrivateKey privKey = KeyStoreHandler.getPrivateKey(KeyStoreHandler.mainAlias);
        /*try {
            privKey = (PrivateKey) RSALibrary.getKey(RSALibrary.PRIVATE_KEY_FILE);
        } catch (Exception e) {
            System.err.println("Error getting the private key: " + e.getMessage());
            System.exit(-1);
        }*/

        System.out.println("1 " + Hex.toHexString(encKeyFile.getEncKey()));
        byte[] keyBytes = KeyStoreHandler.decrypt(KeyStoreHandler.mainAlias, encKeyFile.getEncKey());
        //this.key = RSALibrary.decrypt(encKeyFile.getEncKey(), privKey);
        if (keyBytes == null) {
            throw new Exception("EncKeyFile is corrupted");
        }

        this.key = Arrays.copyOfRange(keyBytes, keyBytes.length - AESLibrary.KEY_SIZE, keyBytes.length);

        System.out.println("2 " + Hex.toHexString(this.key));

        //this.signature = new Signature(encKeyFile.getSignature(), privKey);
        this.signature = new Signature(encKeyFile.getSignature(), KeyStoreHandler.mainAlias);
    }

    public byte[] getKey() {
        return key;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

}
