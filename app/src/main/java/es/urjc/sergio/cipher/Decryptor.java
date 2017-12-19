package es.urjc.sergio.cipher;

import javax.crypto.spec.IvParameterSpec;

import es.urjc.sergio.assembler.Slice;

public class Decryptor {
    private SymmetricCipher cipher;
    private AESLibrary aes;

    public Decryptor(byte[] keyBytes) {
        aes = new AESLibrary();
        cipher = new SymmetricCipher(aes.generateSymmetricKey(keyBytes));
    }

    public Slice decrypt(EncFile file) {
        IvParameterSpec iv = aes.generateIV(file.getIV());
        byte[] decrypted = cipher.decrypt(file.getData(), iv);

        if (decrypted == null)
            return null;

        return Slice.fromBytes(decrypted);
    }
}