package es.urjc.sergio.rsa;

import org.spongycastle.util.encoders.Hex;

import es.urjc.sergio.keystore.KeyStoreHandler;

public class SecureSignature {
    public static final int BYTES = 512;
    private byte[] secSignature;

    public SecureSignature(Signature signature, String alias) {
        byte[] byteSignature = signature.getSignature();
        //System.out.println(byteSignature.length);
        this.secSignature = KeyStoreHandler.encrypt(alias, byteSignature);
        //this.secSignature = RSALibrary.encrypt(signature.getSignature(), pubKey);
    }

    public SecureSignature(byte[] secSignature) {
        this.secSignature = secSignature;
    }

    public byte[] getSignature() {
        return secSignature;
    }

    @Override
    public String toString() {
        return Hex.toHexString(this.secSignature);
    }
}
