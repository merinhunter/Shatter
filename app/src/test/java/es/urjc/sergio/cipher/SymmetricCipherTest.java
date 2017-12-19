package es.urjc.sergio.cipher;

import org.junit.Test;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;

public class SymmetricCipherTest {

    @Test
    public void generateRandomAESKey() {
        AESLibrary aes = new AESLibrary();
        SecretKeySpec key = aes.generateSymmetricKey();

        assertEquals("AES/CBC/PKCS5Padding", key.getAlgorithm());
        assertEquals(AESLibrary.KEY_SIZE, key.getEncoded().length);
    }

    @Test
    public void encryptWithAES() throws Exception {
        byte[] message = "Alice knows Bob's secret.".getBytes();
        AESLibrary aes = new AESLibrary();

        SecretKeySpec key = aes.generateSymmetricKey();
        IvParameterSpec iv = aes.generateIV();

        SymmetricCipher cipher = new SymmetricCipher(key.getEncoded());
        byte[] cipherText = cipher.encrypt(message, iv);

        byte[] plaintext = cipher.decrypt(cipherText, iv);

        assertEquals(new String(message), new String(plaintext));
    }

}