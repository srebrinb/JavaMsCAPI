/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.mcapisignature;

import static bobs.mcapisignature.CertUtils.dump;
import static bobs.mcapisignature.CertUtils.hMyStore;
import static bobs.mcapisignature.SignatureTest.testCertHash;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.junit.Test;
import static org.junit.Assert.*;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author sbalabanov
 */
public class UtilsTest {

    static String testCertHash = "D525114F7A061BA0BC83D94646AE95F855931175";

    public UtilsTest() {
    }

    /**
     * Test of hexStringToByteArray method, of class Utils.
     */
    @Test
    public void testHexStringToByteArray() {
        System.out.println("hexStringToByteArray");
        String s = "";
        byte[] expResult = {15};
        byte[] result = CertUtils.hexStringToByteArray("0F");
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of findCertByHash method, of class Utils.
     */
    @Test
    public void testFindCertByHash() {
        System.out.println("findCertByHash");
        String Sha1Hash = testCertHash;

        Structures.CERT_CONTEXT result = CertUtils.findCertByHash(Sha1Hash);
        byte[] Subject = result.pCertInfo.Subject.pbData.getByteArray(0, result.pCertInfo.Subject.cbData);
        System.out.println(new String(Subject));
    }

    /**
     * Test of certToBytes method, of class Utils.
     */
    @Test
    public void testCertToBytes() {
        System.out.println("certToBytes");
        String Sha1Hash = testCertHash;
        Structures.CERT_CONTEXT cert = CertUtils.findCertByHash(Sha1Hash);
        String expResult = "MIICdDCCAd2gAwIBAgIBCDANBgkqhkiG9w0BAQQFADBdMQswCQYDVQQGEwJCRzEOMAwGA1UECBMFU29maWExDjAMBgNVBAcTBVNvZmlhMQ0wCwYDVQQKEwRCT0JTMQ0wCwYDVQQLEwRCT0JTMRAwDgYDVQQDFAdOQ1NQX0NBMB4XDTE1MTEwNTEzNTYwMFoXDTI1MTEwMjEzNTYwMFowZjELMAkGA1UEBhMCQkcxDjAMBgNVBAgTBVNvZmlhMQ4wDAYDVQQHEwVTb2ZpYTENMAsGA1UEChMEQk9CUzENMAsGA1UECxMEQk9CUzEZMBcGA1UEAxMQRGV0ZWxpbiBFdmxvZ2lldjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4QsnBBknuVTsBIKQA0zlMNA8/0sC+Yh/SLUDWFnMDZyNlxT3sqbk6QgYNtVBM7YIunjiZYKPWtnANrGCx/RSa8ojAJVQLnessxt9nTscqZTTZ2yqqBsM2fFwjtuCW4+qaME7BhQNeEl1Mjj93S02BwSQO1ympTmhsq3/iAMVkbkCAwEAAaM7MDkwHwYDVR0jBBgwFoAUQnIlUNt5M++LuyqsFVyoufSHIwUwCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAwDQYJKoZIhvcNAQEEBQADgYEASOWzwIakf3y0lwRyxI+kk5QEFrRvQF9Ae+0zBfdANEy4y4ApwuQgGk8JcrP+r77HlMHZ9XAFzzL2U19OBPLCiGOqlBDtF4+uoGVk8LCl3eAsA3gQh1k/euMFDxaYkSuHzev2CufOULiMxyg2vcyqKm4SfX1fuMgecmyRbBJL4jc=";
        byte[] result = CertUtils.certToBytes(cert);
        String res = Base64.encodeBase64String(result);
        System.out.println(res);
        assertEquals(expResult, res);

    }

    /**
     * Test of IssuerCertificate method, of class Utils.
     */
    @Test
    public void testIssuerCertificate() {
        System.out.println("IssuerCertificate");
        Structures.CERT_CONTEXT cert = CertUtils.findCertByHash(testCertHash);
        String expResult = "MIIC6TCCAlKgAwIBAgIBADANBgkqhkiG9w0BAQQFADBdMQswCQYDVQQGEwJCRzEOMAwGA1UECBMFU29maWExDjAMBgNVBAcTBVNvZmlhMQ0wCwYDVQQKEwRCT0JTMQ0wCwYDVQQLEwRCT0JTMRAwDgYDVQQDFAdOQ1NQX0NBMB4XDTE1MTEwNDEyMDIwOFoXDTI1MTEwMTEyMDIwOFowXTELMAkGA1UEBhMCQkcxDjAMBgNVBAgTBVNvZmlhMQ4wDAYDVQQHEwVTb2ZpYTENMAsGA1UEChMEQk9CUzENMAsGA1UECxMEQk9CUzEQMA4GA1UEAxQHTkNTUF9DQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1+nSjEjO5bi4e/5K/fXhPjW4YhijXi5LFtOvbrf/A1w1GUrlWsTW55mZFPcPrRwQ8me8lit84+NKi9kHgsteXFnyxq13oqAYTzUsgscpnDuYMUZw+FexvpIILoWYfASUALqcBPvW7gXmnssbwhl/hThK7yISOLQCXbTDF2zfZl8CAwEAAaOBuDCBtTAdBgNVHQ4EFgQUQnIlUNt5M++LuyqsFVyoufSHIwUwgYUGA1UdIwR+MHyAFEJyJVDbeTPvi7sqrBVcqLn0hyMFoWGkXzBdMQswCQYDVQQGEwJCRzEOMAwGA1UECBMFU29maWExDjAMBgNVBAcTBVNvZmlhMQ0wCwYDVQQKEwRCT0JTMQ0wCwYDVQQLEwRCT0JTMRAwDgYDVQQDFAdOQ1NQX0NBggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAK/DVS4VHz6i9oj0GF9GkEcJsJcJAERu4xkwNR3MFbe/FEXwMxQhz/8Du/wLurnY5Z+foeGRQTb9Y9lvk21ilCFQzrdmsBTrBVqBSsazOSE2j3PYFjiUubWbmiWFpy6rjkp754o91oH6zt4IZrLO6PuwKX9ctM7KymaPaC/GR0BE=";
        Structures.CERT_CONTEXT result = CertUtils.IssuerCertificate(cert);
        byte[] certToBytes = CertUtils.certToBytes(result);
        String res = Base64.encodeBase64String(certToBytes);
        System.out.println(res);
        assertEquals(expResult, res);
    }

    @Test
    public void testGetChain() throws SelectCertificateExceprion, CertificateException {
        System.out.println("GetChain");
        Structures.CERT_CONTEXT cert = CertUtils.selectCert();// .findCertByHash(testCertHash);
        List<String> chain = CertUtils.getChain(cert);
        System.out.println(chain.size());
        int i = 0;
        for (String certCA : chain) {
            i++;
            dump(certCA.getBytes(), "src/test/resources/" + i + ".cer");
            System.out.println(CertUtils.getX509CertificateFromB64(certCA).getSubjectDN().getName());
        }
    }

    @Test
    public void testGetThumbprint() {
        System.out.println("GetThumbprint");
        String expResult = testCertHash.toUpperCase();
        Structures.CERT_CONTEXT cert = CertUtils.findCertByHash(testCertHash);

        String thumbprint = CertUtils.getThumbprint(cert);

        assertEquals(expResult, thumbprint);
    }

    @Test
    public void testSelectCert() throws CertificateException {
        System.out.println("SelectCert");
        Structures.CERT_CONTEXT cert;
        try {
            cert = CertUtils.selectCert();
            X509Certificate x509Cert = CertUtils.getX509Certificate(cert);
            System.out.println(x509Cert.getSubjectDN().toString());
        } catch (SelectCertificateExceprion ex) {
            Logger.getLogger(UtilsTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testViewCert() throws SelectCertificateExceprion {
        System.out.println("View Cert");

        Structures.CERT_CONTEXT cert = CertUtils.findCertByHash(testCertHash);
        CertUtils.viewCert(cert, null);
    }

    @Test
    public void testFindCertBySubject() throws CertificateException {
        System.out.println("Find Cert By Subject");
        Structures.CERT_CONTEXT cert = CertUtils.findCertBySubject("Ivan");
        //assertNotNull(cert);
        X509Certificate x509Cert = CertUtils.getX509Certificate(cert);
        System.out.println(x509Cert.getSubjectDN().toString());
        Structures.CERT_CONTEXT certNext = CertUtils.findCertBySubject("Ivan",cert);
        x509Cert = CertUtils.getX509Certificate(certNext);
        System.out.println(x509Cert.getSubjectDN().toString());
    }
    @Test
    public void testgetCertList() {
        System.out.println("getCertList");
        
        List<String> chain=CertUtils.getCertList();
        System.out.println(chain.size());
        int i=0;
        for (String certCA: chain){
            i++;
            dump(certCA.getBytes(),"src/test/resources/"+i+".cer");
        }
    }
    @Test
    public void testOpenMemStore() {
        System.out.println("OpenMemStore");
        Pointer store = CertUtils.openMemStore();
       CertUtils.closeSore(store);
    }
    @Test
    public void testCertAddCertificateContextToStore() throws SelectCertificateExceprion{
      System.out.println("CertAddCertificateContextToStore");
       Pointer store = CertUtils.openMemStore();
       Structures.CERT_CONTEXT cert = CertUtils.findCertBySubject("Ivan");       
       if(!CertUtils.CertAddCertificateContextToStore(store, cert)){
           System.out.println("CertAddCertificateContextToStore:"+Integer.toHexString(Native.getLastError()));
           throw new SelectCertificateExceprion("CertAddCertificateContextToStore:"+Integer.toHexString(Native.getLastError()));
       }
       Crypt32.INST.CertFreeCertificateContext(cert);
       cert = CertUtils.findCertBySubject("Srebrin");
       if(!CertUtils.CertAddCertificateContextToStore(store, cert)){
           System.out.println("CertAddCertificateContextToStore:"+Integer.toHexString(Native.getLastError()));
           throw new SelectCertificateExceprion("CertAddCertificateContextToStore:"+Integer.toHexString(Native.getLastError()));
       }
       Crypt32.INST.CertFreeCertificateContext(cert);
       WinDef.HWND hwnd = User32.INST.GetForegroundWindow();
       Structures.CERT_CONTEXT.ByReference certCont = Cryptui.INST.CryptUIDlgSelectCertificateFromStore(store, hwnd, null, null, 0, 0, null);
       System.out.println("getCertList:"+Integer.toHexString(Native.getLastError()));
       List<String> certs = CertUtils.getCertList(store);
       System.out.println(certs);
      //  CertUtils.viewCert(certCont, "test");
       CertUtils.closeSore(store);
    }
}
