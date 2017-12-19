package es.urjc.sergio.cipher;

import java.security.PrivateKey;

import es.urjc.sergio.rsa.RSALibrary;
import es.urjc.sergio.rsa.Signature;

public class KeyFile {
    private byte[] key;
    private Signature signature;

    public KeyFile(byte[] key) {
        this.key = key;
    }

    public KeyFile(EncKeyFile encKeyFile) throws Exception {
        PrivateKey privKey = null;
        try {
            privKey = (PrivateKey) RSALibrary.getKey(RSALibrary.PRIVATE_KEY_FILE);
        } catch (Exception e) {
            System.err.println("Error getting the private key: " + e.getMessage());
            System.exit(-1);
        }

        this.key = RSALibrary.decrypt(encKeyFile.getEncKey(), privKey);
        if (key == null) {
            throw new Exception("EncKeyFile is corrupted");
        }

        this.signature = new Signature(encKeyFile.getSignature(), privKey);
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
