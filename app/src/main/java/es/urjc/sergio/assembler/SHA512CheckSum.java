package es.urjc.sergio.assembler;

import java.security.MessageDigest;

class SHA512CheckSum {
    private final static String ALGORITHM = "SHA-512";
    private final static String PROVIDER = "BC";

    static byte[] checksum(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(ALGORITHM, PROVIDER);

        digest.update(input);

        return digest.digest();
    }
}