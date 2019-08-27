package com.client;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import org.apache.commons.codec.Charsets;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

public class SignClientTest {
    public static final String SRC = "src/main/resources/test.pdf";
    public static final String CERT = "src/main/resources/econtract.cer";
    public static final String DEST = "results/inputStream1.txt";
    public static final String DEST2_1 = "results/inputStream2_1.txt";
    public static final String DEST2_2 = "results/inputStream2_2.txt";
    @Test
    public void DigestAlgorithmsDigest() throws GeneralSecurityException, IOException {
        digestFile(DEST);
        digestFile(DEST2_1);
        digestFile(DEST2_2);
    }

    private void digestFile(String dest) throws IOException, GeneralSecurityException {
        ExternalDigest externalDigest = new ExternalDigest() {
            @Override
            public MessageDigest getMessageDigest(String hashAlgorithm)
                    throws GeneralSecurityException {
                return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
            }
        };
        FileInputStream fis = new FileInputStream(dest);
        byte hash[] = DigestAlgorithms.digest(fis, externalDigest.getMessageDigest("SHA256"));
        System.out.println("base64 before getAuthenticatedAttributeBytes hash:\n" + new String(Base64.encode(hash), Charsets.UTF_8));
    }

    @Test
    public void Digest() throws IOException, GeneralSecurityException, DocumentException, ParseException {
        FileInputStream fis = new FileInputStream(CERT);
        // We get the self-signed certificate from the client
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate[] chain = new Certificate[1];
        chain[0] = factory.generateCertificate(fis);

        // we create a reader and a stamper
        PdfReader reader = new PdfReader(SRC);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');

        // we create the signature appearance
        PdfSignatureAppearance signatureAppearance = stamper.getSignatureAppearance();
        signatureAppearance.setReason("Test");
        signatureAppearance.setLocation("On a server!");
        signatureAppearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
        signatureAppearance.setCertificate(chain[0]);
        //the time
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Date dt = sdf.parse("2019-08-11");
        Calendar rightNow = Calendar.getInstance();
        rightNow.setTime(dt);
        signatureAppearance.setSignDate(rightNow);

        // we create the signature infrastructure
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        dic.setReason(signatureAppearance.getReason());
        dic.setLocation(signatureAppearance.getLocation());
        dic.setContact(signatureAppearance.getContact());
        dic.setDate(new PdfDate(signatureAppearance.getSignDate()));
        signatureAppearance.setCryptoDictionary(dic);


        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
        signatureAppearance.preClose(exc);


        ExternalDigest externalDigest = new ExternalDigest() {
            @Override
            public MessageDigest getMessageDigest(String hashAlgorithm)
                    throws GeneralSecurityException {
                return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
            }
        };
        InputStream data = signatureAppearance.getRangeStream();

        saveByInputStream(data, DEST2_1);
        InputStream data1 = signatureAppearance.getRangeStream();
        saveByInputStream(data1, DEST2_2);


//        byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
//
//        System.out.println("base64 before getAuthenticatedAttributeBytes hash:\n" + new String(Base64.encode(hash), Charsets.UTF_8));
    }


    private void saveByInputStream(InputStream is,String file) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] data = new byte[256*100];
        int read;
        while ((read = is.read(data)) != -1) {
            baos.write(data, 0, read);
        }
        is.close();
        byte[] pdf = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(pdf);
        fos.close();
    }


}
