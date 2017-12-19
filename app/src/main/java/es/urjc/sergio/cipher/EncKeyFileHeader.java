package es.urjc.sergio.cipher;

import java.nio.ByteBuffer;

import es.urjc.sergio.rsa.SecureSignature;

public class EncKeyFileHeader {
    final static int BYTES = SecureSignature.BYTES;
    private SecureSignature signature;

    EncKeyFileHeader() {
    }

    static EncKeyFileHeader fromBytes(ByteBuffer buffer) {
        byte[] signature = new byte[SecureSignature.BYTES];

        buffer.get(signature);

        EncKeyFileHeader header = new EncKeyFileHeader();
        header.setSignature(new SecureSignature(signature));

        return header;
    }

    public SecureSignature getSignature() {
        return signature;
    }

    public void setSignature(SecureSignature signature) {
        this.signature = signature;
    }

    byte[] toBytes() {
        return this.signature.getSignature();
    }

    @Override
    public String toString() {
        return this.signature.toString();
    }
}
