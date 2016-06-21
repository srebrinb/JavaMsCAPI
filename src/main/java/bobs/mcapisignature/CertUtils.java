/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.mcapisignature;

import static bobs.mcapisignature.Consts.*;
import bobs.mcapisignature.Structures.*;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.ptr.IntByReference;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

/**
 *
 * @author sbalabanov
 */
public class CertUtils {

    static Pointer hMyStore = Crypt32.INST.CertOpenSystemStoreA(null, "MY");

    @Override
    protected void finalize() throws Throwable {
        closeMySore();
    }

    public static Pointer openMemStore() {
        return Crypt32.INST.CertOpenStore("Memory", 0, null, 0, null);
    }

    public static void closeSore(Pointer store) {
        if (store != null) {
            Crypt32.INST.CertCloseStore(store, 0);
        }
    }

    public static void closeMySore() {
        closeSore(hMyStore);
    }

    public static byte[] hexStringToByteArray(String s) {
        s = s.replaceAll(" ", "");
        s = s.replaceAll("-", "");
        s = s.replaceAll(":", "");
        s = s.toUpperCase();
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static CERT_CONTEXT findCertByKeyIdentifier(String KeyIdentifier) {
        byte[] decoded = hexStringToByteArray(KeyIdentifier);
        CRYPT_BIT_BLOB pvFindPara = new CRYPT_BIT_BLOB();
        pvFindPara.pbData = new Memory(decoded.length);
        pvFindPara.pbData.write(0, decoded, 0, decoded.length);
        pvFindPara.cbData = decoded.length;
        CERT_CONTEXT.ByReference cert = Crypt32.INST.CertFindCertificateInStore(hMyStore, 1, 0, CERT_FIND_KEY_IDENTIFIER, pvFindPara, null);
        pvFindPara = null;
        return cert;
    }

    public static CERT_CONTEXT findCertByHash(String Sha1Hash) {
        byte[] decoded = hexStringToByteArray(Sha1Hash);
        CRYPT_BIT_BLOB pvFindPara = new CRYPT_BIT_BLOB();
        pvFindPara.pbData = new Memory(decoded.length);
        pvFindPara.pbData.write(0, decoded, 0, decoded.length);
        pvFindPara.cbData = decoded.length;
        CERT_CONTEXT.ByReference cert = Crypt32.INST.CertFindCertificateInStore(hMyStore, 1, 0, CERT_FIND_HASH, pvFindPara, null);
        pvFindPara = null;
        return cert;
    }

    public static CERT_CONTEXT findCertBySubject(String subject) {
        return findCertBySubject(subject, null);
    }

    public static CERT_CONTEXT findCertBySubject(String subject, CERT_CONTEXT prevCert) {

        CERT_CONTEXT.ByReference cert = Crypt32.INST.CertFindCertificateInStore(hMyStore, 1, 0, CERT_FIND_ANY | CERT_FIND_SUBJECT_STR_A, subject, prevCert);
        // Crypt32.INST.CertCloseStore(hStore, 0);        
        return cert;
    }

    public static boolean CertAddCertificateContextToStore(Pointer store, CERT_CONTEXT cert) {
        boolean res = Crypt32.INST.CertAddCertificateContextToStore(store, cert, 6, null);
        return res;
    }

    public static List<String> getCertList(Pointer store) {
        CERT_CONTEXT.ByReference cert = null;

        List<String> certList = new ArrayList();
        String nullStr = null;
        do {
            cert = Crypt32.INST.CertFindCertificateInStore(store, 1, 0, CERT_FIND_ANY, nullStr, cert);
            if (cert != null) {
                certList.add(certToB64(cert));
            }
        } while (cert != null);
        return certList;
    }

    public static List<String> getCertList() {
        return getCertList(hMyStore);
    }

    public static String certToB64(CERT_CONTEXT cert) {
        return Base64.encodeBase64String(certToBytes(cert));
    }

    public static byte[] certToBytes(CERT_CONTEXT cert) {
        byte[] certIssuerCertBytes = cert.pbCertEncoded.getByteArray(0, cert.cbCertEncoded);
        return certIssuerCertBytes;
    }

    public static CERT_CONTEXT.ByReference IssuerCertificate(CERT_CONTEXT cert) {
        Pointer hStoreCa = Crypt32.INST.CertOpenSystemStoreA(null, "CA");
        IntByReference dwVerificationFlags = new IntByReference();
        CERT_CONTEXT.ByReference certIssuerCert = Crypt32.INST.CertGetIssuerCertificateFromStore(hStoreCa, cert, null, dwVerificationFlags);
        Crypt32.INST.CertCloseStore(hStoreCa, 0);
        return certIssuerCert;
    }

    public static List<String> getChain(CERT_CONTEXT cert) {
        List<String> chain = new ArrayList();
        CERT_CONTEXT pCurrentCert = cert;
        CERT_CONTEXT pIssuerCert = null;
         do{
            chain.add(certToB64(pCurrentCert));
            pIssuerCert = IssuerCertificate(pCurrentCert);

            pCurrentCert = pIssuerCert;
            //if(pIssuerCert !=null)
            // Crypt32.INST.CertFreeCertificateContext(pIssuerCert);
        }while (pCurrentCert != null);

        return chain;
    }

    public static void viewCert(CERT_CONTEXT cert, String title) throws SelectCertificateExceprion {
        if (!Cryptui.INST.CryptUIDlgViewContext(1, cert, null, title, 0, null)) {
            throw new SelectCertificateExceprion("CryptUIDlgViewContext call failed.");
        }
    }

    public static CERT_CONTEXT selectCert() throws SelectCertificateExceprion {
        return selectCert(null, null);
    }

    public static CERT_CONTEXT selectCert(String title, String desc) throws SelectCertificateExceprion {
        WinDef.HWND hwnd = User32.INST.GetForegroundWindow();
        CERT_CONTEXT.ByReference certCont = Cryptui.INST.CryptUIDlgSelectCertificateFromStore(hMyStore, hwnd, title, desc, 0, 0, null);
        if (certCont == null) {
            throw new SelectCertificateExceprion("Select Certificate UI failed.");
        }
        return certCont;
    }

    public static void dump(byte[] content, String file) {
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(content);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 public static X509Certificate getX509CertificateFromB64(String certBase64) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(certBase64)));

        return cert;
    }
    public static X509Certificate getX509Certificate(CERT_CONTEXT pcert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certToBytes(pcert)));

        return cert;
    }

    public static String getThumbprint(CERT_CONTEXT pcert) {
        return DigestUtils.sha1Hex(certToBytes(pcert)).toUpperCase();
    }
}
