package es.urjc.sergio.rsa;

import java.security.Key;
import java.util.zip.DataFormatException;

import es.urjc.sergio.assembler.Slice;
import es.urjc.sergio.cipher.EncFile;
import es.urjc.sergio.cipher.KeyFile;
import es.urjc.sergio.keystore.KeyStoreHandler;

public class Signer {
    private String alias;
    private Key publicKey, privateKey;

    public Signer(String alias) {
        try {
            this.alias = alias;
            this.publicKey = KeyStoreHandler.getPublicKey(alias);
            //publicKey = RSALibrary.getKey(pubKeyPath);
            this.privateKey = KeyStoreHandler.getPrivateKey(KeyStoreHandler.mainAlias);
            //privateKey = RSALibrary.getKey(RSALibrary.PRIVATE_KEY_FILE);
        } catch (Exception e) {
            System.err.println("Signer exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void sign(Slice slice) {
        //RSA_PSS rsapss = new RSA_PSS(privateKey);
        //RSA_PSS rsapss = new RSA_PSS(KeyStoreHandler.mainAlias);

        /*try {
            Signature signature = new Signature(rsapss.sign(slice.getData()));
            slice.getHeader().setSignature(signature);
        } catch (DataFormatException e) {
            System.err.println("Sign exception: " + e.getMessage());
            System.exit(-1);
        }*/

        byte[] byteSignature = KeyStoreHandler.sign(KeyStoreHandler.mainAlias, slice.getData());
        Signature signature = new Signature(byteSignature);
        slice.getHeader().setSignature(signature);
    }

    public void sign(KeyFile keyFile) {
        //RSA_PSS rsapss = new RSA_PSS(privateKey);
        //RSA_PSS rsapss = new RSA_PSS(KeyStoreHandler.mainAlias);

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

        byte[] byteSignature = KeyStoreHandler.sign(KeyStoreHandler.mainAlias,  keyFile.getKey());
        Signature signature = new Signature(byteSignature);
        keyFile.setSignature(signature);
    }

    public void sign(EncFile file) {
        //RSA_PSS rsapss = new RSA_PSS(privateKey);
        //RSA_PSS rsapss = new RSA_PSS(KeyStoreHandler.mainAlias);

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

        byte[] byteSignature = KeyStoreHandler.sign(KeyStoreHandler.mainAlias, file.getIV());
        Signature signature = new Signature(byteSignature);
        SecureSignature secSignature = new SecureSignature(signature, this.alias);

        file.setSignature(secSignature);
    }

    public boolean verify(Slice slice) {
        /*RSA_PSS rsapss = new RSA_PSS(publicKey);

        try {
            if (!rsapss.verify(slice.getData(), slice.getHeader().getSignature().getSignature()))
                return false;
        } catch (DataFormatException e) {
            System.err.println("Verify exception: " + e.getMessage());
            System.exit(-1);
        }*/

        byte[] data = slice.getData();
        byte[] signature = slice.getHeader().getSignature().getSignature();

        return KeyStoreHandler.verify(this.alias, data, signature);

        //return true;
    }

    public boolean verify(KeyFile keyFile) {
        /*RSA_PSS rsapss = new RSA_PSS(publicKey);
        boolean result = false;

        try {
            result = rsapss.verify(keyFile.getKey(), keyFile.getSignature().getSignature());
        } catch (DataFormatException e) {
            System.err.println("Verify DF Exception: " + e.getMessage());
            System.exit(-1);
        } catch (Exception e) {
            System.err.println("Verify Exception: " + e.getMessage());
            System.exit(-1);
        }*/

        byte[] key = keyFile.getKey();
        byte[] signature = keyFile.getSignature().getSignature();

        return KeyStoreHandler.verify(this.alias, key, signature);

        //return result;
    }

    public boolean verify(EncFile file) {
        //RSA_PSS rsapss = new RSA_PSS(publicKey);
        SecureSignature secSignature = file.getSignature();
        Signature signature = new Signature(secSignature, KeyStoreHandler.mainAlias);

        /*try {
            if (!rsapss.verify(file.getIV(), signature.getSignature()))
                return false;
        } catch (DataFormatException e) {
            System.err.println("Verify exception: " + e.getMessage());
            System.exit(-1);
        }*/

        byte[] iv = file.getIV();
        byte[] s = signature.getSignature();

        return KeyStoreHandler.verify(this.alias, iv, s);

        //return true;
    }
}