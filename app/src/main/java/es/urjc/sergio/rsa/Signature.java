package es.urjc.sergio.rsa;

import org.spongycastle.util.encoders.Hex;

import java.security.PrivateKey;

import es.urjc.sergio.keystore.KeyStoreManager;

public class Signature {
    public static final int BYTES = 512;
    private byte[] signature;

    public Signature(byte[] signature) {
        this.signature = signature;
    }

    public Signature(SecureSignature secSignature, String alias) {
        this.signature = KeyStoreManager.decrypt(alias, secSignature.getSignature());
        //this.signature = RSALibrary.decrypt(secSignature.getSignature(), privKey);
    }

    public byte[] getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return Hex.toHexString(this.signature);
    }
}