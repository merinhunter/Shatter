package es.urjc.sergio.cipher;

import java.nio.ByteBuffer;

import es.urjc.sergio.common.Bytes;
import es.urjc.sergio.keystore.KeyStoreHandler;
import es.urjc.sergio.rsa.SecureSignature;

public class EncKeyFile {
    private EncKeyFileHeader header;
    private byte[] encKey;

    public EncKeyFile(KeyFile keyFile, String alias) throws Exception {
        /*PublicKey pubKey = null;

        try {
            //pubKey = (PublicKey) RSALibrary.getKey(pubKeyPath);
            pubKey = KeyStoreHandler.getPublicKey(alias);
        } catch (Exception e) {
            System.err.println("Error getting the public key: " + e.getMessage());
            System.exit(-1);
        }*/

        this.header = new EncKeyFileHeader();
        this.header.setSignature(new SecureSignature(keyFile.getSignature(), alias));

        //this.encKey = RSALibrary.encrypt(keyFile.getKey(), pubKey);
        this.encKey = KeyStoreHandler.encrypt(alias, keyFile.getKey());
    }

    private EncKeyFile(EncKeyFileHeader header, byte[] encKey) {
        this.header = header;
        this.encKey = encKey;
    }

    public static EncKeyFile fromBytes(byte[] src) {

        ByteBuffer buffer = ByteBuffer.wrap(src);
        byte[] encKey = new byte[src.length - EncKeyFileHeader.BYTES];

        EncKeyFileHeader header = EncKeyFileHeader.fromBytes(buffer);
        buffer.get(encKey);

        return new EncKeyFile(header, encKey);
    }

    public SecureSignature getSignature() {
        return this.header.getSignature();
    }

    public void setSignature(SecureSignature signature) {
        this.header.setSignature(signature);
    }

    byte[] getEncKey() {
        return encKey;
    }

    public byte[] toBytes() {
        return Bytes.concat(this.header.toBytes(), this.encKey);
    }
}