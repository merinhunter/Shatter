package es.urjc.sergio.cipher;

import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class AESLibrary {
    final static int KEY_SIZE = 16;
    private final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private SecureRandom random;

    AESLibrary() {
        random = new SecureRandom();
    }

    SecretKeySpec generateSymmetricKey() {
        byte[] keyBytes = new byte[KEY_SIZE];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    SecretKeySpec generateSymmetricKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    IvParameterSpec generateIV() {
        byte[] ivBytes = new byte[KEY_SIZE];
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    IvParameterSpec generateIV(byte[] ivBytes) {
        return new IvParameterSpec(ivBytes);
    }
}