package es.urjc.sergio.keystore;

import org.spongycastle.jce.X509Principal;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

public class KeyStoreManager {
    public final String mainAlias = "main";
    private KeyStore keyStore;

    public KeyStoreManager() {

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
    }

    public boolean existsAlias(String alias) {
        try {
            return this.keyStore.containsAlias(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
    }

    private X509Certificate generateCertificate(PublicKey publicKey, PrivateKey signingKey) throws Exception {
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
    }

    public boolean savePublicKey(String alias, PublicKey publicKey) throws Exception {
        Key mainKey = getPrivateKey(this.mainAlias);

        if (this.keyStore.containsAlias(alias))
            return false;

        if (mainKey != null) {
            X509Certificate certificate = generateCertificate(publicKey, (PrivateKey) mainKey);
            /*KeyStore.TrustedCertificateEntry certEntry =
                    new KeyStore.TrustedCertificateEntry(certificate);
            this.keyStore.setEntry(alias, certEntry, this.protParam);*/
            this.keyStore.setCertificateEntry(alias, certificate);
        }

        return true;
    }

    public boolean savePrivateKey(String alias, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        if (this.keyStore.containsAlias(alias))
            return false;

        X509Certificate certificate = generateCertificate(publicKey, privateKey);
        /*KeyStore.PrivateKeyEntry pkEntry =
                new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});*/
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
    }

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

    public Key getPrivateKey(String alias) throws Exception {
        if(this.keyStore.containsAlias(alias)) {
            System.out.println("Size: " + this.keyStore.size());
            System.out.println("Is key entry?: " + this.keyStore.isKeyEntry(alias));
            System.out.println("Is cert entry?: " + this.keyStore.isCertificateEntry(alias));

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) this.keyStore.getEntry(alias, null);
            //System.out.println("PRIVATE 4: " + pkEntry.getPrivateKey().getEncoded().length);
            System.out.println("PUBLIC 4: " + pkEntry.getCertificate().getPublicKey().getEncoded().length);
            return pkEntry.getPrivateKey();
        }

        /*KeyStore.Entry entry = this.getEntry(alias);

        if (entry != null) {
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) entry;
            return pkEntry.getPrivateKey();
        }*/
        System.out.println(alias + " no existe");
        return null;
    }

    public PublicKey getPublicKey(String alias) throws Exception {
        if(this.keyStore.containsAlias(alias)) {
            Certificate certificate = this.keyStore.getCertificate(alias);
            return certificate.getPublicKey();
        }
        /*KeyStore.Entry entry = this.getEntry(alias);

        if (entry != null) {
            KeyStore.TrustedCertificateEntry certEntry = (KeyStore.TrustedCertificateEntry) entry;
            Certificate cert = certEntry.getTrustedCertificate();
            return cert.getPublicKey();
        }*/

        return null;
    }

    public KeyPair getKeyPair(String alias) throws Exception {
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
        }*/

        return null;
    }
}