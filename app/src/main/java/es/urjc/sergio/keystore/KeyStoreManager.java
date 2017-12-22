package es.urjc.sergio.keystore;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.spongycastle.jce.X509Principal;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;
import es.urjc.sergio.rsa.RSALibrary;

public class KeyStoreManager {
    private static final String TAG = "KeyStoreManager";
    public static final String mainAlias = "main";
    //private final String password = "password";
    //private KeyStore.ProtectionParameter pwdParameter;
    //private KeyStore keyStore;

    /*public KeyStoreManager() {

        try {
            this.keyStore = KeyStore.getInstance("AndroidKeyStore");
            this.keyStore.load(null);
            System.out.println("AndroidKeyStore instantiated correctly");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public KeyStore getKeyStore() {
        return this.keyStore;
    }*/

    public static void exportCertificate(String alias) throws IOException {
        Certificate certificate;
        if (Objects.equals(alias, mainAlias))
            certificate = getPrivateKeyEntry(alias).getCertificate();
        else
            certificate = getCertificateEntry(alias).getTrustedCertificate();

        if (certificate == null)
            return;

        String fileName = alias + ".crt";
        String filePath = FileIO.certificatesPath + fileName;

        File certFile = ExternalStorage.getFile(filePath);
        if (certFile.exists() && !certFile.isDirectory()) {
            certFile.delete();
        }

        FileOutputStream output = new FileOutputStream(certFile);

        try {
            output.write(certificate.getEncoded(), 0, certificate.getEncoded().length);
        } catch (CertificateEncodingException e) {
            Log.e(TAG, e.getMessage(), e);
        } finally {
            if (output != null)
                output.close();
        }
    }

    public static void importCertificate(String alias, String fileName) throws IOException {
        String filePath = FileIO.certificatesPath + fileName;
        File certFile = ExternalStorage.getFile(filePath);
        FileInputStream input = null;

        if(certFile.isFile() && certFile.getName().endsWith(".crt")) {
            input = new FileInputStream(certFile);
        }

        CertificateFactory certificateFactory;
        Certificate certificate;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            certificate = certificateFactory.generateCertificate(input);
        } catch (CertificateException e) {
            Log.e(TAG, e.getMessage(), e);
            return;
        } finally {
            if (input != null)
                input.close();
        }

        try {
            KeyStore keyStore = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER);
            keyStore.load(null);

            keyStore.setCertificateEntry(alias, certificate);
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    public static boolean existsAlias(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER);
            keyStore.load(null);
            return keyStore.containsAlias(alias);
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
            return false;
        }
    }

    public static void generateKeyPair(String alias) {
        try {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA512)
                    //.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setKeySize(SecurityConstants.KEY_SIZE)
                    .build();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, SecurityConstants.KEYSTORE_PROVIDER);
            kpg.initialize(spec);

            kpg.generateKeyPair();
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /*private X509Certificate generateCertificate(PublicKey publicKey, PrivateKey signingKey) throws Exception {
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 1);

        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));
        cert.setSubjectDN(new X509Principal("CN=localhost"));
        cert.setIssuerDN(new X509Principal("CN=localhost"));
        cert.setPublicKey(publicKey);
        cert.setNotBefore(notBefore.getTime());
        cert.setNotAfter(notAfter.getTime());
        cert.setSignatureAlgorithm("SHA1WithRSAEncryption");
        return cert.generate(signingKey, "BC");
    }*/

    /*public boolean savePublicKey(String alias, PublicKey publicKey) throws Exception {
        Key mainKey = getPrivateKey(mainAlias);

        if (this.keyStore.containsAlias(alias))
            return false;

        if (mainKey != null) {
            X509Certificate certificate = generateCertificate(publicKey, (PrivateKey) mainKey);
            KeyStore.TrustedCertificateEntry certEntry =
                    new KeyStore.TrustedCertificateEntry(certificate);
            this.keyStore.setEntry(alias, certEntry, this.protParam);
            this.keyStore.setCertificateEntry(alias, certificate);
        }

        return true;
    }*/

    /*public boolean savePrivateKey(String alias, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        if (this.keyStore.containsAlias(alias))
            return false;

        X509Certificate certificate = generateCertificate(publicKey, privateKey);
        KeyStore.PrivateKeyEntry pkEntry =
                new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});
        System.out.println("PRIVATE 3: " + Arrays.toString(Hex.encode(privateKey.getEncoded())));
        System.out.println("PUBLIC 3: " + Arrays.toString(Hex.encode(publicKey.getEncoded())));
        this.keyStore.setKeyEntry(alias, privateKey, null, new Certificate[]{certificate});

        PrivateKey privKey = (PrivateKey) this.keyStore.getKey(alias, null);
        PublicKey pubKey = this.keyStore.getCertificate(alias).getPublicKey();

        System.out.println("PRIVATE 5: " + Arrays.toString(Hex.encode(privKey.getEncoded())));
        System.out.println("PUBLIC 5: " + Arrays.toString(Hex.encode(pubKey.getEncoded())));
        //this.keyStore.setKeyEntry(alias, privateKey, null, new Certificate[]{certificate});
        //this.keyStore.setEntry(alias, pkEntry, this.protParam);

        return true;
    }*/

    /*public boolean importKey(String alias, Key key) throws Exception {
        KeyPair keyPair = getKeyPair(this.mainAlias);

        if (keyPair != null) {
            X509Certificate certificate = generateCertificate(keyPair);
            keyStore.setKeyEntry(alias, key, null, new Certificate[]{certificate});
            return true;
        }

        return false;
    }*/

    /*private KeyStore.Entry getEntry(String alias) throws Exception {
        if (this.keyStore.containsAlias(alias))
            return this.keyStore.getEntry(alias, this.protParam);

        return null;
    }*/

    private static PrivateKeyEntry getPrivateKeyEntry(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER);
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);

            if (entry == null) {
                Log.w(TAG, "No key found under alias: " + alias);
                return null;
            }

            if (!(entry instanceof PrivateKeyEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return null;
            }

            return (PrivateKeyEntry) entry;
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    private static TrustedCertificateEntry getCertificateEntry(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER);
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);

            if (entry == null) {
                Log.w(TAG, "No key found under alias: " + alias);
                return null;
            }

            if (!(entry instanceof TrustedCertificateEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return null;
            }

            return (TrustedCertificateEntry) entry;
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    public static PublicKey getPublicKey(String alias) {
        PublicKey publicKey;
        if (Objects.equals(alias, mainAlias))
            publicKey = getPrivateKeyEntry(alias).getCertificate().getPublicKey();
        else
            publicKey = getCertificateEntry(alias).getTrustedCertificate().getPublicKey();

        return publicKey;
    }

    public static PrivateKey getPrivateKey(String alias) {
        return getPrivateKeyEntry(alias).getPrivateKey();
    }

    public static byte[] encrypt(String alias, byte[] plaintext) {
        try {
            PublicKey publicKey;
            if (Objects.equals(alias, mainAlias))
                publicKey = getPrivateKeyEntry(alias).getCertificate().getPublicKey();
            else
                publicKey = getCertificateEntry(alias).getTrustedCertificate().getPublicKey();

            Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext);

            //return Base64.encodeToString(RSALibrary.encrypt(plaintext.getBytes(), publicKey), Base64.NO_WRAP);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(String alias, byte[] cipherText) {
        try {
            PrivateKey privateKey = getPrivateKeyEntry(alias).getPrivateKey();
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherText);

            //return Base64.encodeToString(RSALibrary.decrypt(ciphertext.getBytes(), privateKey), Base64.NO_WRAP);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sign(String alias, byte[] m) {
        PrivateKey privateKey = getPrivateKeyEntry(alias).getPrivateKey();

        try {
            Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_ALGORITHM);
            s.initSign(privateKey);
            s.update(m);

            return s.sign();
        } catch (Exception e) {
            System.out.println("Exception signing");
            throw new RuntimeException(e);
        }
    }

    /*public byte[] sign(String alias, byte[] text) throws Exception {
        KeyStore.Entry entry = this.keyStore.getEntry(alias, null);
        if (!(entry instanceof PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return null;
        }

        Signature s = Signature.getInstance("SHA512withRSA/PSS");
        s.initSign(((PrivateKeyEntry) entry).getPrivateKey());
        s.update(text);

        return s.sign();
    }*/

    /*public PrivateKey getPrivateKey(String alias) throws Exception {
        if(this.keyStore.containsAlias(alias)) {
            System.out.println("Size: " + this.keyStore.size());
            System.out.println("Is key entry?: " + this.keyStore.isKeyEntry(alias));
            System.out.println("Is cert entry?: " + this.keyStore.isCertificateEntry(alias));

            KeyStore.Entry entry = this.keyStore.getEntry(alias, null);
            if(!(entry instanceof PrivateKeyEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return null;
            }

            return ((PrivateKeyEntry) entry).getPrivateKey();
            //System.out.println("PRIVATE 4: " + pkEntry.getPrivateKey().getEncoded().length);
            //System.out.println("PUBLIC 4: " + pkEntry.getCertificate().getPublicKey().getEncoded().length);
            //return pkEntry.getPrivateKey();
        }

        /*KeyStore.Entry entry = this.getEntry(alias);

        if (entry != null) {
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) entry;
            return pkEntry.getPrivateKey();
        }
        Log.w(TAG, "Alias doesn't exist");
        return null;
    }*/

    /*public PublicKey getPublicKey(String alias) throws Exception {
        if(this.keyStore.containsAlias(alias)) {
            KeyStore.Entry entry = this.keyStore.getEntry(alias, null);

            if (entry instanceof PrivateKeyEntry) {
                Log.i(TAG, "PrivateKeyEntry");
                return ((PrivateKeyEntry) entry).getCertificate().getPublicKey();
            }

            if (entry instanceof TrustedCertificateEntry) {
                Log.i(TAG, "TrustedCertificateEntry");
                return ((TrustedCertificateEntry) entry).getTrustedCertificate().getPublicKey();
            }

            Log.w(TAG, "No valid entry");
            return null;
        }
        /*KeyStore.Entry entry = this.getEntry(alias);

        if (entry != null) {
            KeyStore.TrustedCertificateEntry certEntry = (KeyStore.TrustedCertificateEntry) entry;
            Certificate cert = certEntry.getTrustedCertificate();
            return cert.getPublicKey();
        }

        Log.w(TAG, "Alias doesn't exist");
        return null;
    }*/

    /*public KeyPair getKeyPair(String alias) throws Exception {
        if(this.keyStore.containsAlias(alias)) {
            PrivateKey privateKey = (PrivateKey) this.keyStore.getKey(alias, null);

            Certificate certificate = this.keyStore.getCertificate(alias);
            PublicKey publicKey = certificate.getPublicKey();

            return new KeyPair(publicKey, privateKey);
        }
        /*KeyStore.Entry entry = this.getEntry(alias);

        if (entry != null) {
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) entry;
            Certificate cert = pkEntry.getCertificate();
            PublicKey publicKey = cert.getPublicKey();
            PrivateKey privateKey = pkEntry.getPrivateKey();
            return new KeyPair(publicKey, privateKey);
        }

        return null;
    }*/

    public static Enumeration<String> getAliases() {
        try {
            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER);
            ks.load(null);

            return ks.aliases();
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    public static void deleteEntry(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER);
            ks.load(null);

            ks.deleteEntry(alias);
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    private static Cipher getCipher() throws Exception {
        return Cipher.getInstance(
                String.format("%s/%s/%s",
                        SecurityConstants.TYPE_RSA,
                        SecurityConstants.BLOCKING_MODE,
                        SecurityConstants.PADDING_TYPE));
    }

    public interface SecurityConstants {
        String KEYSTORE_PROVIDER = "AndroidKeyStore";
        String TYPE_RSA = "RSA";
        String PADDING_TYPE = "PKCS1Padding";
        String BLOCKING_MODE = "NONE";
        String SIGNATURE_ALGORITHM = "SHA512withRSA/PSS";
        int KEY_SIZE = 4096;
    }
}