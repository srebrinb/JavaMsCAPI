/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

/**
 *
 * @author sbalabanov
 */
public class Consts {

    final static int PROV_GOST_2001_DH = 75;
    final static int CRYPT_VERIFYCONTEXT = 0xF0000000;
    final static int CRYPT_SILENT = 64;
    final static int CRYPT_MESSAGE_SILENT_KEYSET_FLAG = 64;
    final static int PP_NAME = 4;
    final static int AT_KEYEXCHANGE = 1;
    final static int AT_SIGNATURE = 2;
    final static int KP_CERTIFICATE = 26;
    final static int PP_KEYEXCHANGE_PIN = 32;
    final static int PP_SIGNATURE_PIN = 33;
    final static int X509_ASN_ENCODING = 1;
    final static int PKCS_7_ASN_ENCODING = 0x10000;
    final static int CERT_KEY_PROV_INFO_PROP_ID = 2;
    final static int CERT_STORE_ADD_REPLACE_EXISTING = 3;
    final static String szOID_CP_GOST_R3411 = "1.2.643.2.2.9";
    final static String szOID_RSA_SHA1RSA = "1.2.840.113549.1.1.5";
    final static String szOID_RSA_SHA256RSA = "1.2.840.113549.1.1.11";
    //TODO add all alg
    final static int CERT_COMPARE_MASK = 0xFFFF;
    final static int CERT_COMPARE_SHIFT = 16;
    final static int CERT_COMPARE_ANY = 0;
    final static int CERT_COMPARE_SHA1_HASH = 1;
    final static int CERT_COMPARE_NAME = 2;
    final static int CERT_COMPARE_ATTR = 3;
    final static int CERT_COMPARE_MD5_HASH = 4;
    final static int CERT_COMPARE_PROPERTY = 5;
    final static int CERT_COMPARE_PUBLIC_KEY = 6;
    final static int CERT_COMPARE_HASH = CERT_COMPARE_SHA1_HASH;
    final static int CERT_COMPARE_NAME_STR_A = 7;
    final static int CERT_COMPARE_NAME_STR_W = 8;
    final static int CERT_COMPARE_KEY_SPEC = 9;
    final static int CERT_COMPARE_ENHKEY_USAGE = 10;
    final static int CERT_COMPARE_CTL_USAGE = CERT_COMPARE_ENHKEY_USAGE;
    final static int CERT_COMPARE_SUBJECT_CERT = 11;
    final static int CERT_COMPARE_ISSUER_OF = 12;
    final static int CERT_COMPARE_EXISTING = 13;
    final static int CERT_COMPARE_SIGNATURE_HASH = 14;
    final static int CERT_COMPARE_KEY_IDENTIFIER = 15;
    final static int CERT_COMPARE_CERT_ID = 16;
    final static int CERT_COMPARE_CROSS_CERT_DIST_POINTS = 17;

    final static int CERT_COMPARE_PUBKEY_MD5_HASH = 18;

    final static int CERT_COMPARE_SUBJECT_INFO_ACCESS = 19;
    final static int CERT_COMPARE_HASH_STR = 20;
    final static int CERT_COMPARE_HAS_PRIVATE_KEY = 21;

    final static int CERT_INFO_VERSION_FLAG = 1;
    final static int CERT_INFO_SERIAL_NUMBER_FLAG = 2;
    final static int CERT_INFO_SIGNATURE_ALGORITHM_FLAG = 3;
    final static int CERT_INFO_ISSUER_FLAG = 4;
    final static int CERT_INFO_NOT_BEFORE_FLAG = 5;
    final static int CERT_INFO_NOT_AFTER_FLAG = 6;
    final static int CERT_INFO_SUBJECT_FLAG = 7;
    final static int CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG = 8;
    final static int CERT_INFO_ISSUER_UNIQUE_ID_FLAG = 9;
    final static int CERT_INFO_SUBJECT_UNIQUE_ID_FLAG = 10;
    final static int CERT_INFO_EXTENSION_FLAG = 11;

    final static int CERT_FIND_ANY = (CERT_COMPARE_ANY << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_SHA1_HASH = (CERT_COMPARE_SHA1_HASH << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_MD5_HASH = (CERT_COMPARE_MD5_HASH << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_SIGNATURE_HASH = (CERT_COMPARE_SIGNATURE_HASH << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_KEY_IDENTIFIER = (CERT_COMPARE_KEY_IDENTIFIER << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_HASH = CERT_FIND_SHA1_HASH;
    final static int CERT_FIND_PROPERTY = (CERT_COMPARE_PROPERTY << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_PUBLIC_KEY = (CERT_COMPARE_PUBLIC_KEY << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_SUBJECT_NAME = (CERT_COMPARE_NAME << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG);
    final static int CERT_FIND_SUBJECT_ATTR = (CERT_COMPARE_ATTR << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG);
    final static int CERT_FIND_ISSUER_NAME = (CERT_COMPARE_NAME << CERT_COMPARE_SHIFT | CERT_INFO_ISSUER_FLAG);
    final static int CERT_FIND_ISSUER_ATTR = (CERT_COMPARE_ATTR << CERT_COMPARE_SHIFT | CERT_INFO_ISSUER_FLAG);
    final static int CERT_FIND_SUBJECT_STR_A = (CERT_COMPARE_NAME_STR_A << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG);
    final static int CERT_FIND_SUBJECT_STR_W = (CERT_COMPARE_NAME_STR_W << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG);
    final static int CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W;
    final static int CERT_FIND_ISSUER_STR_A = (CERT_COMPARE_NAME_STR_A << CERT_COMPARE_SHIFT | CERT_INFO_ISSUER_FLAG);
    final static int CERT_FIND_ISSUER_STR_W = (CERT_COMPARE_NAME_STR_W << CERT_COMPARE_SHIFT | CERT_INFO_ISSUER_FLAG);
    final static int CERT_FIND_ISSUER_STR = CERT_FIND_ISSUER_STR_W;
    final static int CERT_FIND_KEY_SPEC = (CERT_COMPARE_KEY_SPEC << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_ENHKEY_USAGE = (CERT_COMPARE_ENHKEY_USAGE << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_CTL_USAGE = CERT_FIND_ENHKEY_USAGE;
    final static int CERT_FIND_SUBJECT_CERT = (CERT_COMPARE_SUBJECT_CERT << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_ISSUER_OF = (CERT_COMPARE_ISSUER_OF << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_EXISTING = (CERT_COMPARE_EXISTING << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_CERT_ID = (CERT_COMPARE_CERT_ID << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_CROSS_CERT_DIST_POINTS = (CERT_COMPARE_CROSS_CERT_DIST_POINTS << CERT_COMPARE_SHIFT);

    final static int CERT_FIND_PUBKEY_MD5_HASH = (CERT_COMPARE_PUBKEY_MD5_HASH << CERT_COMPARE_SHIFT);

    final static int CERT_FIND_SUBJECT_INFO_ACCESS = (CERT_COMPARE_SUBJECT_INFO_ACCESS << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_HASH_STR = (CERT_COMPARE_HASH_STR << CERT_COMPARE_SHIFT);
    final static int CERT_FIND_HAS_PRIVATE_KEY = (CERT_COMPARE_HAS_PRIVATE_KEY << CERT_COMPARE_SHIFT);
}
