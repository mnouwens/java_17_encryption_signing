package eu.europa.ec.digit.boris.asic.util;

import no.difi.asic.KeyStoreType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * @author Xavier VILRET on 17/08/2021
 */
public class SignatureHelper extends no.difi.asic.SignatureHelper {

    /* ---- Constants ---- */

    /* ---- Instance Variables ---- */

    protected KeyStore keyStore;

    /* ---- Constructors ---- */

    public SignatureHelper(File keyStoreFile, String keyStorePassword, String keyPassword) throws IOException {
        super(keyStoreFile, keyStorePassword, keyPassword);
    }

    public SignatureHelper(File keyStoreFile, String keyStorePassword, String keyAlias, String keyPassword) throws IOException {
        super(keyStoreFile, keyStorePassword, keyAlias, keyPassword);
    }

    public SignatureHelper(InputStream keyStoreStream, String keyStorePassword, String keyAlias, String keyPassword) {
        super(keyStoreStream, keyStorePassword, keyAlias, keyPassword);
    }

    public SignatureHelper(File keyStoreFile, String keyStorePassword, KeyStoreType keyStoreType, String keyAlias, String keyPassword) throws IOException {
        super(keyStoreFile, keyStorePassword, keyStoreType, keyAlias, keyPassword);
    }

    public SignatureHelper(InputStream keyStoreStream, String keyStorePassword, KeyStoreType keyStoreType, String keyAlias, String keyPassword) {
        super(keyStoreStream, keyStorePassword, keyStoreType, keyAlias, keyPassword);
    }

    public SignatureHelper(Provider provider) {
        super(provider);
    }

    public SignatureHelper(KeyStore keyStore, String keyStorePassword, String keyAlias, String keyPassword) {
        super(getProvider());
        this.keyStore = keyStore;
        this.loadCertificate(this.loadKeyStore(null, keyStorePassword, DEFAULT_KEY_STORE_TYPE), keyAlias, keyPassword);
    }

    /* ---- Business Methods ---- */

    @Override
    protected KeyStore loadKeyStore(InputStream keyStoreStream, String keyStorePassword, KeyStoreType keyStoreType) {
        if (this.keyStore != null) {
            return keyStore;
        } else {
            return super.loadKeyStore(keyStoreStream, keyStorePassword, keyStoreType);
        }
    }

    /* ---- Getters and Setters ---- */

    private static Provider getProvider() {
        Provider provider;

        if (Security.getProvider("BC") != null) {
            provider = Security.getProvider("BC");
        } else {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }

        return provider;
    }
}
