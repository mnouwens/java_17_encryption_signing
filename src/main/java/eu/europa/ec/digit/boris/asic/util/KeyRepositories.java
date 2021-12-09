package eu.europa.ec.digit.boris.asic.util;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.Random;

/**
 * @author Xavier VILRET on 17/08/2021
 */
public class KeyRepositories {

    /* ---- Constants ---- */

    /* ---- Instance Variables ---- */

    private KeyRepository senderKeyRepository;

    private KeyRepository receiverKeyRepository;

    /* ---- Constructors ---- */

    public KeyRepositories() {
        initialize();
    }

    /* ---- Business Methods ---- */

    private void initialize() {
        try {

//            KeyStore keyStore = KeyStore.getInstance("JKS");
//            keyStore.load(null, null);
            {
                KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA");
                kpGenerator.initialize(2048);
                KeyPair keyPair = kpGenerator.generateKeyPair();

                X500Name issuerName = new X500Name("CN=Sender,O=Sender Organisation,L=Sender City,C=FR");
                PrivateKey privateKey = keyPair.getPrivate();

                JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                        issuerName,
                        BigInteger.valueOf(System.currentTimeMillis()),
                        Date.from(Instant.now()), Date.from(Instant.now().plusMillis(1096 * 24 * 60 * 60)),
                        issuerName, keyPair.getPublic());
                ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
                X509CertificateHolder certHolder = builder.build(signer);
                X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
                PublicKey publicKey = certificate.getPublicKey();

                String senderPrivateKeyPassword = "senderPrivateKeyPassword";
                String senderKSPassword = "senderPwd";
                String senderAlias = "senderAlias";
                KeyStore senderKeyStore = createKeyStore(senderKSPassword, senderAlias, privateKey, senderPrivateKeyPassword, certificate);
                senderKeyRepository = new KeyRepository(senderKeyStore, senderKSPassword, senderAlias, senderPrivateKeyPassword, certificate);

            }
            {
                KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA");
                kpGenerator.initialize(2048);
                KeyPair keyPair = kpGenerator.generateKeyPair();

                X500Name issuerName = new X500Name("CN=Receiver,O=Receiver Organisation,L=Receiver City,C=DE");
                PrivateKey privateKey = keyPair.getPrivate();

                JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                        issuerName,
                        BigInteger.valueOf(System.currentTimeMillis()),
                        Date.from(Instant.now()), Date.from(Instant.now().plusMillis(1096 * 24 * 60 * 60)),
                        issuerName, keyPair.getPublic());
                ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
                X509CertificateHolder certHolder = builder.build(signer);
                X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
                PublicKey publicKey = certificate.getPublicKey();

                String receiverPrivateKeyPassword = "receiverPrivateKeyPassword";
                String receiverKSPassword = "receiverPwd";
                String receiverAlias = "receiverAlias";
                KeyStore receiverKeyStore = createKeyStore(receiverKSPassword, receiverAlias, privateKey, receiverPrivateKeyPassword, certificate);
                receiverKeyRepository = new KeyRepository(receiverKeyStore, receiverKSPassword, receiverAlias, receiverPrivateKeyPassword, certificate);

            }
//            X509Certificate senderCertificate = certificateGenerator.getSelfCertificate(new X500Name("CN=Sender,O=Sender Organisation,L=Sender City,C=FR"), certificateValidityInSeconds);
//            PrivateKey senderPrivateKey = certificateGenerator.getPrivateKey();
//            String senderPrivateKeyPassword = "senderPrivateKeyPassword";
//            X509Certificate receiverCertificate = certificateGenerator.getSelfCertificate(new X500Name("CN=Receiver,O=Receiver Organisation,L=Receiver City,C=DE"), certificateValidityInSeconds);
//            PrivateKey receiverPrivateKey = certificateGenerator.getPrivateKey();
//            String receiverPrivateKeyPassword = "receiverPrivateKeyPassword";


//            String receiverKSPassword = "receiverPwd";
//            String receiverAlias = "receiverAlias";
//            KeyStore receiverKeyStore = createKeyStore(receiverKSPassword, receiverAlias, receiverPrivateKey, receiverPrivateKeyPassword, receiverCertificate);



        } catch ( CertificateException | NoSuchAlgorithmException | OperatorCreationException e) {
            e.printStackTrace();
        }
    }

    private KeyStore createKeyStore(String keyStorePassword, String keyAlias, PrivateKey privateKey, String privateKeyPassword, X509Certificate selfSignedCertificate) {
        KeyStore result = null;

        try {
            result = KeyStore.getInstance(KeyStore.getDefaultType());
            result.load(null, keyStorePassword.toCharArray());
            X509Certificate[] certificateChain = new X509Certificate[]{
                    selfSignedCertificate
            };
            result.setKeyEntry(keyAlias, privateKey, privateKeyPassword.toCharArray(), certificateChain);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            noSuchAlgorithmException.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return result;
    }

    /* ---- Getters and Setters ---- */

    public KeyRepository getSenderKeyRepository() {
        return senderKeyRepository;
    }

    public KeyRepository getReceiverKeyRepository() {
        return receiverKeyRepository;
    }

}
