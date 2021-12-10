package eu.europa.ec.digit.boris.asic;

import eu.europa.ec.digit.boris.asic.util.KeyRepositories;
import eu.europa.ec.digit.boris.asic.util.KeyRepository;
import eu.europa.ec.digit.boris.asic.util.SignatureHelper;
import no.difi.asic.AsicReader;
import no.difi.asic.AsicReaderFactory;
import no.difi.asic.AsicWriter;
import no.difi.asic.AsicWriterFactory;
import no.difi.asic.MimeType;
import no.difi.asic.extras.CmsEncryptedAsicReader;
import no.difi.asic.extras.CmsEncryptedAsicWriter;
import no.difi.commons.asic.jaxb.asic.Certificate;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Xavier VILRET on 16/08/2021
 */
public class EncryptedASiCEDemo {

    private static final KeyRepositories keyRepositories = new KeyRepositories();

    private static final String borisXMLMessage = "<xml></xml>";

    public static void main(String[] args) {
        try {
                String asicContainerToSendByteArrayOutputStream = generateASiCEContainerToSend();

            validateAndDecryptAsicContainerOnReceiverSide(asicContainerToSendByteArrayOutputStream);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    private static String generateASiCEContainerToSend() throws IOException {
        final String DEFAULT_BORIS_MESSAGE_FILENAME = "BORIS-Message.xml";



        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        AsicWriter asicWriter = AsicWriterFactory.newFactory().newContainer(byteArrayOutputStream);

        // fetch the certificate of the recipient of the encrypted message
        // this originally comes from IKAR but it's most certainly cached locally for performance.
//        X509Certificate recipientCertificate = senderKeyRepository.getExternalCertificate();
        X509Certificate recipientCertificate = keyRepositories.getReceiverKeyRepository().getExternalCertificate();

        // Create the ASiC-E container writer
        CmsEncryptedAsicWriter writer = new CmsEncryptedAsicWriter(asicWriter, recipientCertificate);

        // add the BORIS XML Message to the ASiC-E Container
        InputStream borisMessageInputStream = new ByteArrayInputStream(borisXMLMessage.getBytes(Charset.forName("UTF-8")));
        writer.addEncrypted(borisMessageInputStream, DEFAULT_BORIS_MESSAGE_FILENAME);
        // important step in order to distinguish the BORIS XML Message from the other files in the container (attachments)
        writer.setRootEntryName(DEFAULT_BORIS_MESSAGE_FILENAME);

        // Add attachments (if any)
        // Rule : the entry name in the ASiC-E container is the attachment reference mentioned in the BORIS XML message

        File add1 = new File("attachment1.txt");
        writer.addEncrypted(add1, "attachment-1", MimeType.forString("text/plain"));
        writer.addEncrypted(new File("attachment2.txt"), "attachment-2", MimeType.forString("text/plain"));

        KeyRepository senderKeyRepository = keyRepositories.getSenderKeyRepository();
        // Sign the ASiC-E container using the private key of the sender
        writer.sign(new SignatureHelper(senderKeyRepository.getKeyStore(), senderKeyRepository.getKeyStorePassword(), senderKeyRepository.getKeyAlias(), senderKeyRepository.getPrivateKeyPassword()));

        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
//        return byteArrayOutputStream.toByteArray();
//        return IOUtils.toString(byteArrayOutputStream.toByteArray(), "UTF-8");
    }

    private static void validateAndDecryptAsicContainerOnReceiverSide(String stringData) {
        KeyRepository receiverKeyRepository = keyRepositories.getReceiverKeyRepository();
        KeyRepository senderKeyRepository = keyRepositories.getSenderKeyRepository();
        try {

            InputStream asicContainerByteArrayInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(stringData));
            AsicReader asicReader = AsicReaderFactory.newFactory().open(asicContainerByteArrayInputStream);

            PrivateKey receiverPrivateKey = (PrivateKey) receiverKeyRepository.getKeyStore().getKey(receiverKeyRepository.getKeyAlias(), receiverKeyRepository.getPrivateKeyPassword().toCharArray());

            CmsEncryptedAsicReader reader = new CmsEncryptedAsicReader(asicReader, receiverPrivateKey);

            // get all files from the container
            Map<String, ByteArrayOutputStream> fileMap = readAsicContainer(reader);

            // Validate attached certificate: it should match the certificate attached to the supposed sender received from IKAR
            if (isSenderCertificateValid(reader, senderKeyRepository.getExternalCertificate())) {
                System.out.println("Sender certificate is valid");

                String rootFileName = reader.getAsicManifest().getRootfile();
                for (String entryName : fileMap.keySet()) {
                    StringBuilder sb = new StringBuilder();

                    if (entryName.equals(rootFileName)) {
                        // the current entry is the BORIS XML message
                        sb.append("BORIS message - ");
                    } else {
                        // the current entry is an attachment
                        // the entry name is the attachment reference mentioned in the BORIS XML message
                        sb.append("Attachment - ");
                    }

                    sb.append(entryName).append(": ").append(new String(fileMap.get(entryName).toByteArray(), Charset.forName("UTF-8")));

                    System.out.println(sb.toString());
                }
            } else {
                // handle validation error
                System.err.println("Invalid bundled sender certificate in ASiC-E container");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            noSuchAlgorithmException.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, ByteArrayOutputStream> readAsicContainer(CmsEncryptedAsicReader reader) throws IOException {
        Map<String, ByteArrayOutputStream> result = new HashMap<String, ByteArrayOutputStream>();

        // Important note: read ASiC-E Container until the end
        // => this will trigger the signature validation to complete

        String nextFile = null;
        while ((nextFile = reader.getNextFile())!= null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            reader.writeFile(baos);

            result.put(nextFile, baos);
        }

        return result;
    }

    private static boolean isSenderCertificateValid(AsicReader reader, X509Certificate senderCertificateFromIKAR) throws CertificateEncodingException {
        boolean result = false;

        List<Certificate> certificateList = reader.getAsicManifest().getCertificate();
        if (certificateList.size() == 1) {
            // only one receiver per message in the context of BORIS, so only one certificate is expected
            byte[] encodedSenderCertificateFromPayload = certificateList.get(0).getCertificate();
            byte[] encodedCertificateFromIKAR = senderCertificateFromIKAR.getEncoded();

            result = Arrays.equals(encodedSenderCertificateFromPayload, encodedCertificateFromIKAR);
        }

        return result;
    }
}
