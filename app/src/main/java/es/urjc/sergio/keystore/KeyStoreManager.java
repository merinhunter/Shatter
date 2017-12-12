package es.urjc.sergio.keystore;

import org.spongycastle.jce.X509Principal;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class KeyStoreManager {
    public final String mainAlias = "main";
    private KeyStore keyStore;

    public KeyStoreManager() {
        try {
            this.keyStore = KeyStore.getInstance("AndroidKeyStore");
            this.keyStore.load(null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public KeyStore getKeyStore() {
        return this.keyStore;
    }

    private static X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 1);

        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));
        cert.setSubjectDN(new X509Principal("CN=localhost"));
        cert.setIssuerDN(new X509Principal("CN=localhost"));
        cert.setPublicKey(keyPair.getPublic());
        cert.setNotBefore(notBefore.getTime());
        cert.setNotAfter(notAfter.getTime());
        cert.setSignatureAlgorithm("SHA1WithRSAEncryption");
        PrivateKey signingKey = keyPair.getPrivate();
        return cert.generate(signingKey, "SC");
    }

    public boolean importKey(String alias, Key key) throws Exception {
        KeyPair keyPair = getKeyPair(this.mainAlias);

        if (keyPair != null) {
            X509Certificate certificate = generateCertificate(keyPair);
            keyStore.setKeyEntry(alias, key, null, new Certificate[]{certificate});
            return true;
        }

        return false;
    }

    public KeyPair getKeyPair(String alias) throws Exception {
        Key key = getKey(alias);

        if (key instanceof PrivateKey) {
            Certificate certificate = keyStore.getCertificate(alias);
            PublicKey publicKey = certificate.getPublicKey();

            return new KeyPair(publicKey, (PrivateKey) key);
        }

        return null;
    }

    public Key getKey(String alias) throws Exception {
        if (keyStore.containsAlias(alias))
            return keyStore.getKey(alias, null);

        return null;
    }

}