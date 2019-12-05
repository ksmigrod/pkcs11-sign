package pl.gov.mofnet.giif.spikes.pkcs11sign;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    private static final Logger logger = Logger.getLogger(Main.class.getName());

    // Wstaw lokalizację bibloteki implementującej PKCS#11
    private static final String PKCS11_LIBRARY = "/home/ksm/src/securefile/szafir-plugin/src/main/binaries/linux-x64/pkcs11/cryptoCertum3PKCS-2.0.0.43.r2-MS.so";
    // Wstaw numer slotu
    private static final long TOKEN_SLOT = 1L;

    // Tutaj możesz wstawić swój numer PIN, jeżeli pozostawisz tekst "USTAW_PIN",
    // to użyty zostanie ConsoleCallbackHandler, który zapyta o PIN w terminalu.
    private static final String TOKEN_PIN_STRING = "USTAW_PIN";
    private static final char[] TOKEN_PIN = TOKEN_PIN_STRING.toCharArray();

    // Tutaj wstaw numer Twojego certyfikatu kwalifikowanego.
    private static final BigInteger CERT_SERIAL = new BigInteger("0123456789abcdef", 16);

    // Certyfikat do szyfrowania
    private static final String ENCRYPTION_CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIG0DCCBLigAwIBAgIQSVemUhcVjMhEjlQA5XClTDANBgkqhkiG9w0BAQsFADCB\n" +
            "pzELMAkGA1UEBhMCUEwxFDASBgNVBAgTC21hem93aWVja2llMREwDwYDVQQHEwhX\n" +
            "YXJzemF3YTEfMB0GA1UECgwWTWluaXN0ZXJzdHdvIEZpbmFuc8OzdzEyMDAGA1UE\n" +
            "CxMpR2VuZXJhbG55IEluc3Bla3RvciBJbmZvcm1hY2ppIEZpbmFuc293ZWoxGjAY\n" +
            "BgNVBAMTEUdJSUYgVEVTVCBDQSAyMDE5MB4XDTE5MDMyMjEyNTQwMFoXDTIwMDMy\n" +
            "MjEyNTQwMFowgcoxCzAJBgNVBAYTAlBMMRQwEgYDVQQIEwttYXpvd2llY2tpZTER\n" +
            "MA8GA1UEBxMIV2Fyc3phd2ExHzAdBgNVBAoMFk1pbmlzdGVyc3R3byBGaW5hbnPD\n" +
            "s3cxMjAwBgNVBAsTKUdlbmVyYWxueSBJbnNwZWt0b3IgSW5mb3JtYWNqaSBGaW5h\n" +
            "bnNvd2VqMT0wOwYDVQQDDDRURVNUT1dZIERvIHN6eWZyb3dhbmlhIHBsaWvDs3cg\n" +
            "ZG8gc3lzdGVtdSB0ZXN0b3dlZ28uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
            "CgKCAQEAxpBhrKAWxFs3DkYK4HKBb+sTTscMFa6nDehP6k4GAfOYgN+9tnca50Ki\n" +
            "Tor9V7uNW8ruEqWYi+8anal7LDADy+O6KwwQljnuFsrUc11Zb0QG7ppnex6Go1Kh\n" +
            "f/bJPe7TiHSl48BxvBMdypljDle8rpndIzCFYfxD89JcXu4rdhmnsOaahAASBCxi\n" +
            "evrv6TLXNtbgZ4eobtVbnm3c4P5hInPA78O9VpeOqE2RSjwyVxt6e61jpqV5itpO\n" +
            "FvYHomtLET8NkCYkWaja9NY4TxiRPm7Lz0QP++xVgd7AeHI1+ofCIWRI1AN3NZE3\n" +
            "22DCssSsx5Ru1hG+l3RcLOb1Sz/oUwIDAQABo4IB0TCCAc0wDAYDVR0TAQH/BAIw\n" +
            "ADAdBgNVHQ4EFgQUPRuseD0ggHuw2KXqUSY4E8MiJ98wgeMGA1UdIwSB2zCB2IAU\n" +
            "U8V9LSGiO14PLqINE+wlPGU3jpWhga2kgaowgacxCzAJBgNVBAYTAlBMMRQwEgYD\n" +
            "VQQIEwttYXpvd2llY2tpZTERMA8GA1UEBxMIV2Fyc3phd2ExHzAdBgNVBAoMFk1p\n" +
            "bmlzdGVyc3R3byBGaW5hbnPDs3cxMjAwBgNVBAsTKUdlbmVyYWxueSBJbnNwZWt0\n" +
            "b3IgSW5mb3JtYWNqaSBGaW5hbnNvd2VqMRowGAYDVQQDExFHSUlGIFRFU1QgQ0Eg\n" +
            "MjAxOYIQSVemUhcVjMhEjlQA5XClSjAOBgNVHQ8BAf8EBAMCBSAwRAYDVR0fBD0w\n" +
            "OzA5oDegNYYzaHR0cDovL3Rlc3QuZ2lpZi5tb2ZuZXQuZ292LnBsL3BraS9HSUlG\n" +
            "LVRFU1QtQ0EuY3JsME8GCCsGAQUFBwEBBEMwQTA/BggrBgEFBQcwAoYzaHR0cDov\n" +
            "L3Rlc3QuZ2lpZi5tb2ZuZXQuZ292LnBsL3BraS9HSUlGLVRFU1QtQ0EuY3J0MBEG\n" +
            "CWCGSAGG+EIBAQQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAgEAZkiRBl1dHhPGh8lo\n" +
            "uv8pyTt+Y4nCbStB31gEVRJYHh+ASYSO0NNK2XgBqsacNxVZNgMxwKKL7cKd19Uf\n" +
            "UasR9LZow/X+fQVKP4rORLSx0QE53KMjz8fshaHDU0qDAdappo+LQB5PUOFFW8RN\n" +
            "AaEBvVDpv/Tb3+BjNq4zzJBD0m8UIv+3sAf0mbzIQh+9Zb+s2WKaPRfV/rBU0oB0\n" +
            "oTPAvd56CKz457lsowDxIxcD4qjg5bB3BT/aqpmitpCtsAUU9csI0gGx+ALLeyN4\n" +
            "CPKMrw4H3HvGan6KeXwF9xQKPan2ST/gi40XTvEhABFkPbnMUJannh20IXF2ufEv\n" +
            "BhN/Puj7wEbFKFWVNCn1+lzpmx+IndJ5jaqAxaBDkeVka/5TKqhvih5lot94Gz9Y\n" +
            "Sy7yk4ye7n48NYXtzpLnxeg+79/mDNAAL8hJBvp/0+I2/sIvbaZV76hFtDBfxWFG\n" +
            "SQL8rZ/3v4jB8YYYvDShNL1aHiSb/8GSydYMzfw5syWJX7NjKia5qiSMSMwNz9tV\n" +
            "kGjXJUpcbWlL3bH3FmRR4Vd/WtkNZjXAI8KHR1EbyORD5c/vSxaKZ0WhhBlnqGR+\n" +
            "clQR0Mu3U9wOmKBhg7czoTwck1TDnTU9u+06cRebQe0rO0hKzbzQlDwc3Sn5bzFd\n" +
            "xr/BJV7K4nvRkEuNoWEDiMgT0EY=\n" +
            "-----END CERTIFICATE-----\n";

    private static Provider loadProvider(String libraryFile, long slot) {
        String config = String.format("name = %s%nlibrary = %s%nslot = %d%n",
                "PodpisElektroniczny", libraryFile, slot);
        InputStream providerParameter = new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8));
        Provider loadedProvider = new sun.security.pkcs11.SunPKCS11(providerParameter);
        return loadedProvider;
    }

    private static KeyStore getKeyStore(Provider provider) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keystore = null;
        if ("USTAW_PIN".equals(TOKEN_PIN_STRING)) {
            KeyStore.CallbackHandlerProtection chp = new KeyStore.CallbackHandlerProtection(new ConsoleCallbackHandler());
            KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider, chp);
            keystore = builder.getKeyStore();
        } else {
            keystore = KeyStore.getInstance("PKCS11", provider);
            keystore.load(null, TOKEN_PIN);
        }
        return keystore;
    }

    private static String getAliasByCertificateSerialNumber(KeyStore keyStore, BigInteger certSerial) throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            logger.log(Level.INFO, "Alias: {0}", alias);
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            logger.log(Level.INFO, "  Certificate Serial: {0}", cert.getSerialNumber().toString(16));
            if (CERT_SERIAL.equals(cert.getSerialNumber())) {
                return alias;
            }
        }
        throw new IllegalStateException("Brak certyfikatu o numerze " + certSerial.toString(16) + " w KeyStore.");
    }

    private static X509Certificate toX509Certificate(String pem) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, CMSException, OperatorCreationException {
        Provider provider = loadProvider(PKCS11_LIBRARY, TOKEN_SLOT);
        KeyStore keyStore = getKeyStore(provider);
        String alias = getAliasByCertificateSerialNumber(keyStore, CERT_SERIAL);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = null;
        if ("USTAW_PIN".equals(TOKEN_PIN_STRING)) {
            privateKey = (PrivateKey) keyStore.getKey(alias, null); // jeżeli używamy CallbackHandler
        } else {
            privateKey = (PrivateKey) keyStore.getKey(alias, TOKEN_PIN);
        }

        try (OutputStream result = new FileOutputStream("/home/ksm/test.signed");
             OutputStream signed =
                     new SigningStreamBuilder()
                             .setSigningCertificate(certificate)
                             .setSigningProvider(provider)
                             .setSigningKey(privateKey)
                             .setSignatureAlgorithm("SHA256withRSA")
                             .setDestination(result)
                             .build();
             InputStream source = new FileInputStream("/home/ksm/test.plain")) {
            IOUtils.copy(source, signed);
        }

        try (OutputStream result = new FileOutputStream("/home/ksm/test.encrypted");
             OutputStream encrypted =
                     new EncrypingStreamBuilder()
                             .setRecipientCertificate(toX509Certificate(ENCRYPTION_CERTIFICATE_PEM))
                             .setContentOID(CMSObjectIdentifiers.compressedData)
                             .setDestination(result)
                             .build();
             OutputStream compressed =
                     new CompressingStreamBuilder()
                             .setContentOID(CMSObjectIdentifiers.signedData)
                             .setDestination(encrypted)
                             .build();
             OutputStream signed =
                     new SigningStreamBuilder()
                             .setSigningCertificate(certificate)
                             .setSigningProvider(provider)
                             .setSigningKey(privateKey)
                             .setSignatureAlgorithm("SHA256withRSA")
                             .setDestination(compressed)
                             .build();
             InputStream source = new FileInputStream("/home/ksm/test.plain")) {
            IOUtils.copy(source, signed);
        }
    }

    private static class SigningStreamBuilder {

        private X509Certificate signingCertificate;
        private PrivateKey signingKey;
        private Provider signingProvider;

        private String signatureAlgorithm = "SHA256withRSA";

        private OutputStream destination;

        public SigningStreamBuilder() {
        }

        public SigningStreamBuilder setSigningCertificate(X509Certificate signingCertificate) {
            this.signingCertificate = signingCertificate;
            return this;
        }

        public SigningStreamBuilder setSigningKey(PrivateKey signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        public SigningStreamBuilder setSigningProvider(Provider signingProvider) {
            this.signingProvider = signingProvider;
            return this;
        }

        public SigningStreamBuilder setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        public SigningStreamBuilder setDestination(OutputStream destination) {
            this.destination = destination;
            return this;
        }

        private CMSAttributeTableGenerator buildSignedAttributeTableGenerator(X509Certificate signingCert) throws CertificateEncodingException, NoSuchAlgorithmException, IOException {
            ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
            signedAttributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(constructSigningCertificateV2(signingCert))));
            AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            return new DefaultSignedAttributeTableGenerator(signedAttributesTable);
        }

        private SigningCertificateV2 constructSigningCertificateV2(X509Certificate cert) throws CertificateEncodingException, IOException, NoSuchAlgorithmException {
            byte[] certEncoded = cert.getEncoded();
            final X500Name issuerX500Name = new X509CertificateHolder(certEncoded).getIssuer();
            final GeneralName generalName = new GeneralName(issuerX500Name);
            final GeneralNames generalNames = new GeneralNames(generalName);
            final BigInteger serialNumber = cert.getSerialNumber();
            final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);
            final ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), this.digest(certEncoded), issuerSerial);
            return new SigningCertificateV2(essCertIDv2);
        }

        private byte[] digest(byte[] data) throws NoSuchAlgorithmException {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(data);
        }

        public OutputStream build() throws IOException, CertificateEncodingException, CMSException, OperatorCreationException, NoSuchAlgorithmException {

            final ContentSigner contentSigner =
                    new JcaContentSignerBuilder(signatureAlgorithm)
                            .setProvider(signingProvider)
                            .build(signingKey);

            final DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider(signingProvider)
                            .build();

            final SignerInfoGenerator signerInfoGenerator =
                    new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                            .setSignedAttributeGenerator(buildSignedAttributeTableGenerator(signingCertificate))
                            .build(contentSigner, signingCertificate);

            final CMSSignedDataStreamGenerator sgen = new CMSSignedDataStreamGenerator();
            sgen.addSignerInfoGenerator(signerInfoGenerator);
            sgen.addCertificates(new JcaCertStore(Collections.singleton(signingCertificate)));
            return sgen.open(destination, true);
        }
    }

    private static class EncrypingStreamBuilder {

        private ASN1ObjectIdentifier symmetricEncryptionAlgorithm = CMSAlgorithm.AES256_CBC;
        private X509Certificate recipientCertificate;
        private ASN1ObjectIdentifier contentOID = CMSObjectIdentifiers.data;
        private OutputStream destination;

        public EncrypingStreamBuilder() {
        }

        public EncrypingStreamBuilder setSymmetricEncryptionAlgorithm(ASN1ObjectIdentifier symmetricEncryptionAlgorithm) {
            this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
            return this;
        }

        public EncrypingStreamBuilder setRecipientCertificate(X509Certificate recipientCertificate) {
            this.recipientCertificate = recipientCertificate;
            return this;
        }

        public EncrypingStreamBuilder setContentOID(ASN1ObjectIdentifier contentOID) {
            this.contentOID = contentOID;
            return this;
        }

        public EncrypingStreamBuilder setDestination(OutputStream destination) {
            this.destination = destination;
            return this;
        }

        public OutputStream build() throws CertificateEncodingException, CMSException, IOException {

            final JceKeyTransRecipientInfoGenerator recipientInfoGenerator =
                    new JceKeyTransRecipientInfoGenerator(recipientCertificate);

            final OutputEncryptor outputEncryptor =
                    new JceCMSContentEncryptorBuilder(symmetricEncryptionAlgorithm).build();

            CMSEnvelopedDataStreamGenerator egen = new CMSEnvelopedDataStreamGenerator();
            egen.addRecipientInfoGenerator(recipientInfoGenerator);
            return egen.open(contentOID, destination, outputEncryptor);
        }
    }

    private static class CompressingStreamBuilder {


        private ASN1ObjectIdentifier contentOID = CMSObjectIdentifiers.data;
        private OutputStream destination;
        private OutputCompressor outputCompressor = new ZlibCompressor();

        public CompressingStreamBuilder() {
        }

        public CompressingStreamBuilder setContentOID(ASN1ObjectIdentifier contentOID) {
            this.contentOID = contentOID;
            return this;
        }

        public CompressingStreamBuilder setDestination(OutputStream destination) {
            this.destination = destination;
            return this;
        }

        public CompressingStreamBuilder setOutputCompressor(OutputCompressor outputCompressor) {
            this.outputCompressor = outputCompressor;
            return this;
        }

        public OutputStream build() throws IOException {
            CMSCompressedDataStreamGenerator cgen =
                    new CMSCompressedDataStreamGenerator();
            return cgen.open(contentOID, destination, outputCompressor);
        }
    }
}
