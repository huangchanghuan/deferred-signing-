package com.client;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import org.apache.commons.codec.Charsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * pdf分离签署例子
 */
public class SignerClient {
    static String PreSignURL;
    static String PostSignURL;
    public static final String CERT = "src/main/resources/econtract.cer";
    public static final String PFX = "src/main/resources/econtract.jks";
    public static final String PROPERTY = "src/main/resources/key.properties";
    public static final String DEST = "results/signed.pdf";
    public static final String IMAGE_DEST = "src/main/resources/sign.png";
    static String key_password;


    public static final String SRC = "src/main/resources/test.pdf";

    private String message;

    //保存共享变量
    private HashMap<String, Object> shareMap = new HashMap<>();

    public static void readProperty(String propertyPath) {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(propertyPath));
            key_password = properties.getProperty("PASSWORD");
            PreSignURL = properties.getProperty("presign-url");
            PostSignURL = properties.getProperty("postsign-url");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] getHash(String cert) throws IOException, CertificateException {
        try {
            FileInputStream fis = new FileInputStream(cert);
            // We get the self-signed certificate from the client
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate[] chain = new Certificate[1];
            chain[0] = factory.generateCertificate(fis);

            // we create a reader and a stamper
            PdfReader reader = new PdfReader(SRC);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');

            // we create the signature appearance
            PdfSignatureAppearance sap = stamper.getSignatureAppearance();
            sap.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

            //图片
            Image image = Image.getInstance(IMAGE_DEST); //使用png格式透明图片
//            image.scaleAbsolute(200,200);
            sap.setSignatureGraphic(image);


            sap.setReason("sim签电子平台签署");
            sap.setLocation("中国广州市");
            sap.setVisibleSignature(new Rectangle(100, 500, 300, 700), 1, "sig");
            sap.setCertificate(chain[0]);
            //the time
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date dt = sdf.parse("2019-08-11");
            Calendar rightNow = Calendar.getInstance();
            rightNow.setTime(dt);
            sap.setSignDate(rightNow);

            // we create the signature infrastructure
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dic.setReason(sap.getReason());
            dic.setLocation(sap.getLocation());
            dic.setContact(sap.getContact());
            dic.setDate(new PdfDate(sap.getSignDate()));
            sap.setCryptoDictionary(dic);
            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
            sap.preClose(exc);
            ExternalDigest externalDigest = new ExternalDigest() {
                @Override
                public MessageDigest getMessageDigest(String hashAlgorithm)
                        throws GeneralSecurityException {
                    return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
                }
            };
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
            InputStream data = sap.getRangeStream();
            byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
            System.out.println("sha256 后字节长度:"+hash.length);
            System.out.println("base64 before getAuthenticatedAttributeBytes hash:\n" + new String(Base64.encode(hash), Charsets.UTF_8));

            // we get OCSP and CRL for the cert
            OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
            OcspClient ocspClient = new OcspClientBouncyCastle(ocspVerifier);
            byte[] ocsp = null;
            if (chain.length >= 2 && ocspClient != null) {
                ocsp = ocspClient.getEncoded((X509Certificate) chain[0], (X509Certificate) chain[1], null);
            }
            Collection<byte[]> crlBytes = null;
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);
            System.out.println("签名前字节长度:"+sh.length);


            // We store the objects we'll need for post signing in a shareMap
            shareMap.put("sgn", sgn);
            shareMap.put("hash", hash);
            shareMap.put("ocsp", ocsp);
            shareMap.put("sap", sap);
            shareMap.put("baos", baos);

            // we write the hash that needs to be signed to the HttpResponse output
            return sh;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return  null;
    }

    public byte[] Sign(byte[] hash, String pfx) throws KeyStoreException,
            IOException, UnrecoverableKeyException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, CertificateException {
        byte[] data = new byte[256];

        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream input = new FileInputStream(pfx);
        char[] kp = key_password.toCharArray();
        ks.load(input, kp);
        String alias = (String) ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, key_password.toCharArray());
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        sig.update(hash);
        data = sig.sign();

        return data;
    }

    public void getSignedPDF(byte[] signature, String file) throws IOException, DocumentException {
        // we get the objects we need for postsigning from the shareMap
        PdfPKCS7 sgn = (PdfPKCS7) shareMap.get("sgn");
        byte[] hash = (byte[]) shareMap.get("hash");
        byte[] ocsp = (byte[]) shareMap.get("ocsp");
        PdfSignatureAppearance sap = (PdfSignatureAppearance) shareMap.get("sap");
        ByteArrayOutputStream os = (ByteArrayOutputStream) shareMap.get("baos");

        // we read the signed bytes
        // we complete the PDF signing process
        sgn.setExternalDigest(signature, null, "RSA");
        Collection<byte[]> crlBytes = null;
        TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle("http://timestamp.gdca.com.cn/tsa", null, null);
        byte[] encodedSig = sgn.getEncodedPKCS7(hash, tsaClient, ocsp, crlBytes, MakeSignature.CryptoStandard.CMS);
        byte[] paddedSig = new byte[8192];
        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        sap.close(dic2);

        byte[] pdf = os.toByteArray();
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(pdf);
        fos.close();
    }

    public static void main(String args[]) throws IOException, DocumentException {
        readProperty(PROPERTY);
        SignerClient sc = new SignerClient();
        // 1. get hash to be signed
        byte[] hash = null;
        try {
            hash = sc.getHash(CERT);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        System.out.println("base64 hash:\n" + new String(Base64.encode(hash), Charsets.UTF_8));

        // 2. sign hash with private key
        byte[] signature = null;
        try {
            signature = sc.Sign(hash, PFX);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("签名后字节长度:"+signature.length);
        System.out.println("base64 signed hash:\n" + new String(Base64.encode(signature), Charsets.UTF_8));

        // 3. post signed hash to get the signed PDF
        sc.getSignedPDF(signature, DEST);

    }
}
