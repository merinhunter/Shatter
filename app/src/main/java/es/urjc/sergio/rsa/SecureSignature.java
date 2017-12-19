package es.urjc.sergio.rsa;

import org.spongycastle.util.encoders.Hex;

import java.security.PublicKey;

public class SecureSignature {
    public static final int BYTES = 512;
    private byte[] secSignature;

    public SecureSignature(Signature signature, PublicKey pubKey) {
        this.secSignature = RSALibrary.encrypt(signature.getSignature(), pubKey);
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
