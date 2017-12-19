package es.urjc.sergio.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCipher {
    private final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private final String PROVIDER = "BC";

    private SecretKeySpec key;

    SymmetricCipher(byte[] keyBytes) {
        key = new SecretKeySpec(keyBytes, ALGORITHM);
    }

    SymmetricCipher(SecretKeySpec key) {
        this.key = key;
    }

    public byte[] getKey() {
        return key.getEncoded();
    }

    public byte[] encrypt(byte[] plaintext, IvParameterSpec iv) {
        byte[] cipherText;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            cipherText = cipher.doFinal(plaintext);
        } catch (Exception e) {
            System.err.println("Encrypt exception: " + e.getMessage());
            return null;
        }

        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText, IvParameterSpec iv) {
        byte[] plaintext;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            plaintext = cipher.doFinal(cipherText);
        } catch (Exception e) {
            System.err.println("Decrypt exception: " + e.getMessage());
            return null;
        }

        return plaintext;
    }
}
