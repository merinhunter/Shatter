package es.urjc.sergio.cipher;

import java.nio.ByteBuffer;

import es.urjc.sergio.common.Bytes;
import es.urjc.sergio.rsa.SecureSignature;

public class EncFileHeader {
    final static int BYTES = AESLibrary.KEY_SIZE + SecureSignature.BYTES;
    private byte[] IV;
    private SecureSignature IV_signature;

    EncFileHeader(byte[] iv) {
        this.IV = iv;
    }

    static EncFileHeader fromBytes(ByteBuffer buffer) {
        byte[] IV = new byte[AESLibrary.KEY_SIZE];
        byte[] signature = new byte[SecureSignature.BYTES];

        buffer.get(IV);
        buffer.get(signature);

        EncFileHeader header = new EncFileHeader(IV);
        header.setIV_signature(new SecureSignature(signature));

        return header;
    }

    SecureSignature getIV_signature() {
        return IV_signature;
    }

    void setIV_signature(SecureSignature iV_signature) {
        IV_signature = iV_signature;
    }

    byte[] getIV() {
        return IV;
    }

    byte[] toBytes() {
        return Bytes.concat(this.IV, this.IV_signature.getSignature());
    }

    @Override
    public String toString() {
        return new String(this.IV) + "|" + this.IV_signature.toString();
    }
}