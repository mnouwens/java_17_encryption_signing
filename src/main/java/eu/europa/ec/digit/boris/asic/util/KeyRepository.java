package eu.europa.ec.digit.boris.asic.util;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * @author Xavier VILRET on 17/08/2021
 */
public class KeyRepository {

    /* ---- Constants ---- */

    /* ---- Instance Variables ---- */

    private KeyStore keyStore;
    private String keyStorePassword;
    private String keyAlias;
    private String privateKeyPassword;

    private X509Certificate externalCertificate;

    /* ---- Constructors ---- */

    public KeyRepository(KeyStore keyStore,
                         String keyStorePassword,
                         String keyAlias,
                         String privateKeyPassword,
                         X509Certificate externalCertificate) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
        this.keyAlias = keyAlias;
        this.privateKeyPassword = privateKeyPassword;
        this.externalCertificate = externalCertificate;
    }

    /* ---- Business Methods ---- */

    /* ---- Getters and Setters ---- */

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public X509Certificate getExternalCertificate() {
        return externalCertificate;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }
}
