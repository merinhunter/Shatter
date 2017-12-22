package es.urjc.sergio.rsa;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.zip.DataFormatException;

import es.urjc.sergio.assembler.Slice;
import es.urjc.sergio.cipher.EncFile;
import es.urjc.sergio.cipher.KeyFile;
import es.urjc.sergio.keystore.KeyStoreManager;

public class Signer {
    private String alias;
    private Key publicKey, privateKey;

    public Signer(String alias) {
        try {
            this.alias = alias;
            publicKey = KeyStoreManager.getPublicKey(alias);
            //publicKey = RSALibrary.getKey(pubKeyPath);
            privateKey = KeyStoreManager.getPrivateKey(KeyStoreManager.mainAlias);
            //privateKey = RSALibrary.getKey(RSALibrary.PRIVATE_KEY_FILE);
        } catch (Exception e) {
            System.err.println("Signer exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void sign(Slice slice) {
        //RSA_PSS rsapss = new RSA_PSS(privateKey);
        //RSA_PSS rsapss = new RSA_PSS(KeyStoreManager.mainAlias);

        /*try {
            Signature signature = new Signature(rsapss.sign(slice.getData()));
            slice.getHeader().setSignature(signature);
        } catch (DataFormatException e) {
            System.err.println("Sign exception: " + e.getMessage());
            System.exit(-1);
        }*/

        Signature signature = new Signature(KeyStoreManager.sign(KeyStoreManager.mainAlias, slice.getData()));
        slice.getHeader().setSignature(signature);
    }

    public void sign(KeyFile keyFile) {
        //RSA_PSS rsapss = new RSA_PSS(privateKey);
        //RSA_PSS rsapss = new RSA_PSS(KeyStoreManager.mainAlias);

        /*try {
            Signature signature = new Signature(rsapss.sign(keyFile.getKey()));
            keyFile.setSignature(signature);
        } catch (DataFormatException e) {
            System.err.println("Sign DF Exception: " + e.getMessage());
            System.exit(-1);
        } catch (Exception e) {
            System.err.println("Sign Exception: " + e.getMessage());
            System.exit(-1);
        }*/

        Signature signature = new Signature(KeyStoreManager.sign(KeyStoreManager.mainAlias, keyFile.getKey()));
        keyFile.setSignature(signature);
    }

    public void sign(EncFile file) {
        //RSA_PSS rsapss = new RSA_PSS(privateKey);
        //RSA_PSS rsapss = new RSA_PSS(KeyStoreManager.mainAlias);

        /*try {
            Signature signature = new Signature(rsapss.sign(file.getIV()));
            SecureSignature secSignature = new SecureSignature(signature, this.alias);

            file.setSignature(secSignature);
        } catch (DataFormatException e) {
            System.err.println("Sign DF Exception: " + e.getMessage());
            System.exit(-1);
        } catch (Exception e) {
            System.err.println("Sign Exception: " + e.getMessage());
            System.exit(-1);
        }*/

        Signature signature = new Signature(KeyStoreManager.sign(KeyStoreManager.mainAlias, file.getIV()));
        SecureSignature secSignature = new SecureSignature(signature, this.alias);

        file.setSignature(secSignature);
    }

    public boolean verify(Slice slice) {
        RSA_PSS rsapss = new RSA_PSS(publicKey);

        try {
            if (!rsapss.verify(slice.getData(), slice.getHeader().getSignature().getSignature()))
                return false;
        } catch (DataFormatException e) {
            System.err.println("Verify exception: " + e.getMessage());
            System.exit(-1);
        }

        return true;
    }

    public boolean verify(KeyFile keyFile) {
        RSA_PSS rsapss = new RSA_PSS(publicKey);
        boolean result = false;

        try {
            result = rsapss.verify(keyFile.getKey(), keyFile.getSignature().getSignature());
        } catch (DataFormatException e) {
            System.err.println("Verify DF Exception: " + e.getMessage());
            System.exit(-1);
        } catch (Exception e) {
            System.err.println("Verify Exception: " + e.getMessage());
            System.exit(-1);
        }

        return result;
    }

    public boolean verify(EncFile file) {
        RSA_PSS rsapss = new RSA_PSS(publicKey);
        SecureSignature secSignature = file.getSignature();
        Signature signature = new Signature(secSignature, KeyStoreManager.mainAlias);

        try {
            if (!rsapss.verify(file.getIV(), signature.getSignature()))
                return false;
        } catch (DataFormatException e) {
            System.err.println("Verify exception: " + e.getMessage());
            System.exit(-1);
        }

        return true;
    }
}