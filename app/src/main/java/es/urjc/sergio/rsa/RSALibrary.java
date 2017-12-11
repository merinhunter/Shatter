package es.urjc.sergio.rsa;

import org.spongycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
//import javax.xml.bind.DatatypeConverter;

public class RSALibrary {
    // String to hold the name of the encryption algorithm.
    public final static String ALGORITHM = "RSA";

    // String to hold the name of the security provider.
    public final static String PROVIDER = "SC";

    // String to hold the name of the RSA keys path.
    public final static String keysPath = "";

    // String to hold the name of the private key file.
    public final static String PRIVATE_KEY_FILE = keysPath + "private.key";

    // String to hold name of the public key file.
    public final static String PUBLIC_KEY_FILE = keysPath + "public.key";

    public final static int KEY_SIZE = 4096;

    private final static int LINE_LENGTH = 64;

    private SecureRandom random;

    public RSALibrary() {
        random = new SecureRandom();
    }

    public static Key getKey(String path) throws Exception {
        Key key;
        Boolean isPublic = false;
        StringBuilder base64encoded = new StringBuilder();
        String line;

        BufferedReader reader = new BufferedReader(new FileReader(new File(path)));
        String header = reader.readLine();

        if ("-----BEGIN PUBLIC KEY-----".equals(header)) {
            isPublic = true;
        } else if (!"-----BEGIN RSA PRIVATE KEY-----".equals(header)) {
            reader.close();
            throw new Exception("Key file main wrong: " + path + " got: " + header);
        }

        try {
            for (line = reader.readLine(); ; line = reader.readLine()) {
                base64encoded.append(line);
                if (line.length() != LINE_LENGTH) {
                    line = reader.readLine();
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new Exception("Key file missing footer: " + path);
        } finally {
            reader.close();
        }

        if ((isPublic && !"-----END PUBLIC KEY-----".equals(line))
                || (!isPublic && !"-----END RSA PRIVATE KEY-----".equals(line))) {
            throw new Exception("Key file has wrong footer: " + path);
        }

        //byte[] keyBytes = DatatypeConverter.parseBase64Binary(base64encoded);
        byte[] keyBytes = Hex.decode(base64encoded.toString());

        if (isPublic) {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
            key = keyFactory.generatePublic(keySpec);
        } else {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
            key = keyFactory.generatePrivate(keySpec);
        }

        return key;
    }

    private static void saveKey(Key key, String path) throws IOException {
        byte[] encoded = key.getEncoded();
        //String base64encoded = new String(DatatypeConverter.printBase64Binary(encoded));
        String base64encoded = Hex.toHexString(encoded);
        StringBuilder keyString = new StringBuilder();

        int i;
        for (i = 0; i < base64encoded.length() / LINE_LENGTH; i++) {
            keyString.append(base64encoded.substring(i * LINE_LENGTH, i * LINE_LENGTH + LINE_LENGTH)).append("\n");
        }
        keyString.append(base64encoded.substring(i * LINE_LENGTH)).append("\n");

        if (key instanceof PrivateKey) {
            keyString = new StringBuilder("-----BEGIN RSA PRIVATE KEY-----\n" + keyString + "-----END RSA PRIVATE KEY-----\n");
        } else {
            keyString = new StringBuilder("-----BEGIN PUBLIC KEY-----\n" + keyString + "-----END PUBLIC KEY-----\n");
        }

        DataOutputStream o = new DataOutputStream(new FileOutputStream(path));
        o.write(keyString.toString().getBytes());
        o.flush();
        o.close();
    }

    public void generateKeys() throws IOException {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            keyGen.initialize(KEY_SIZE, random);
            KeyPair keyPair = keyGen.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            saveKey(publicKey, PUBLIC_KEY_FILE);
            saveKey(privateKey, PRIVATE_KEY_FILE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    public static Key generatePublicKey(BigInteger N, BigInteger E) throws Exception {
        Key key;

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(N, E);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        key = keyFactory.generatePublic(keySpec);

        return key;
    }

    public static Key generatePrivateKey(BigInteger N, BigInteger E) throws Exception {
        Key key;

        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(N, E);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        key = keyFactory.generatePrivate(keySpec);

        return key;
    }

    public static byte[] encrypt(byte[] plainText, PublicKey key) {
        byte[] cipherText;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            cipherText = cipher.doFinal(plainText);
        } catch (Exception e) {
            System.err.println("Failed to encrypt: " + e.getMessage());
            return null;
        }

        return cipherText;
    }

    public static byte[] decrypt(byte[] cipherText, PrivateKey key) {
        byte[] plainText;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key);

            plainText = cipher.doFinal(cipherText);
        } catch (Exception e) {
            System.err.println("Failed to encrypt: " + e.getMessage());
            return null;
        }

        return plainText;
    }
}
