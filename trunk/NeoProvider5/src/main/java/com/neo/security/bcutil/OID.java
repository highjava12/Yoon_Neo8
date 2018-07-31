package com.neo.security.bcutil;

import java.util.Properties;
import java.util.StringTokenizer;

/*-----------------------------------------------------------------------------------
  ��      �� : OID ������ ���� Ŭ����
  ��  ��  �� : ���߽�
  ��  ��  �� : 2001-03-01
  ��  ��  �� : Ȳ����
  ��  ��  �� : 2004-04-21
  ����  ���� : ecdsa��� OID�߰�
 -----------------------------------------------------------------------------------*/

public class OID
{
	public static final String nullOID			= "";

	public static final String kcdsa			= "1.2.410.200004.1.1";
	public static final String kcdsa1			= "1.2.410.200004.1.21";

/*  Message Digest Algorithm Object Identifier */
	public static final String sha				= "1.3.14.3.2.26";
	public static final String sha1				= "1.3.14.3.2.26";
	public static final String sha256			= "2.16.840.1.101.3.4.2.1";
	public static final String sha384			= "2.16.840.1.101.3.4.2.2";
	public static final String sha512			= "2.16.840.1.101.3.4.2.3";
	public static final String sha224			= "2.16.840.1.101.3.4.2.4";
	public static final String md2				= "1.2.840.113549.2.2";
	public static final String md4				= "1.2.840.113549.2.4";
	public static final String md5				= "1.2.840.113549.2.5";
    public static final String hmacWithSHA1         = "1.2.840.113549.2.7";
    public static final String hmacWithSHA224       = "1.2.840.113549.2.8";
    public static final String hmacWithSHA256       = "1.2.840.113549.2.9";
    public static final String hmacWithSHA384       = "1.2.840.113549.2.10";;
    public static final String hmacWithSHA512       = "1.2.840.113549.2.11";;

	public static final String has160			= "1.2.410.200004.1.2";

	
/*  Digital Signature Algorithm Object Identifier */
	public static final String md5WithRSAEncryption		= "1.2.840.113549.1.1.4";
	public static final String sha1WithRSAEncryption	= "1.2.840.113549.1.1.5";
	public static final String sha2WithRSAEncryption	= "1.2.840.113549.1.1.11";
	public static final String sha256WithRSAEncryption	= "1.2.840.113549.1.1.11";
	public static final String sha384WithRSAEncryption	= "1.2.840.113549.1.1.12";
	public static final String sha512WithRSAEncryption	= "1.2.840.113549.1.1.13";
	public static final String has160WithKCDSA		= "1.2.410.200004.1.8";
	public static final String sha1WithKCDSA		= "1.2.410.200004.1.9";
	public static final String has160WithRSAEncryption	= "1.2.410.200004.1.20";
	public static final String has160WithKCDSA1		= "1.2.410.200004.1.22";
	public static final String sha1WithKCDSA1		= "1.2.410.200004.1.23";
	public static final String has160WithECDSA		= "1.2.410.200004.1.24";
	
	public static final String ecdsaWithSHA1		= "1.2.840.10045.4.1";

	/*
	 * ���� ������ : Ȳ����
	 * �� �� �� �� : 2004-03-10
	 * �� �� �� �� : ecdsa �˰?��  oid
	 */
	//ecdsa
	public static final String ECDSA				= "1.2.840.10045.2.1";
	//Curves over GF(2m) by X9.62: c2pnb163v1(curve nickname)
	public static final String c2pnb163v1			= "1.2.840.10045.3.0.1";

/*  Asymmetric Encryption Algorithm Object Identifier */
	public static final String rsaEncryption		= "1.2.840.113549.1.1.1";

/*  Symmetric Encryption Algorithm Object Identifier */
	public static final String des_cbc			= "1.3.14.3.2.7";
	public static final String des_ede_cbc			= "1.2.840.113549.3.7";

	public static final String seed_ecb			= "1.2.410.200004.1.3";
	public static final String seed_cbc			= "1.2.410.200004.1.4";
	public static final String seed_ofb			= "1.2.410.200004.1.5";
	public static final String seed_cfb			= "1.2.410.200004.1.6";
	
	public static final String aria_cbc         = "1.2.410.200004.5.2.100.2";

	

	/**
	 * ARIA 알고리즘 OID 
	 * 표준: A Description of the ARIA Encryption Algorithm draft-nsri-aria-02.
	 * added by jylee91 on 2012-07-31
	 */
	
	public static final String aria				= "1.2.410.200046.1.1";
	public static final String aria128_ecb				= "1.2.410.200046.1.1";
	public static final String aria128_cbc				= "1.2.410.200046.1.2";
	public static final String aria128_cfb				= "1.2.410.200046.1.3";
	public static final String aria128_ofb				= "1.2.410.200046.1.4";
	public static final String aria128_ctr				= "1.2.410.200046.1.5";

	public static final String aria192_ecb				= "1.2.410.200046.1.6";
	public static final String aria192_cbc				= "1.2.410.200046.1.7";
	public static final String aria192_cfb				= "1.2.410.200046.1.8";
	public static final String aria192_ofb				= "1.2.410.200046.1.9";
	public static final String aria192_ctr				= "1.2.410.200046.1.10";

	public static final String aria256_ecb				= "1.2.410.200046.1.11";
	public static final String aria256_cbc				= "1.2.410.200046.1.12";
	public static final String aria256_cfb				= "1.2.410.200046.1.13";
	public static final String aria256_ofb				= "1.2.410.200046.1.14";
	public static final String aria256_ctr				= "1.2.410.200046.1.15";
	
	/**
	 * AES 알고리즘 OID 추가 by jylee91 on 2012-07-31
	 */
	public static final String aes				= "2.16.840.1.101.3.4.1";
	public static final String aes128_ecb		= aes + ".1";
	public static final String aes128_cbc		= aes + ".2";
	public static final String aes128_ofb		= aes + ".3";
	public static final String aes128_cfb		= aes + ".4";
	
	public static final String aes192_ecb		= aes + ".21";
	public static final String aes192_cbc		= aes + ".22";
	public static final String aes192_ofb		= aes + ".23";
	public static final String aes192_cfb		= aes + ".24";
	
	public static final String aes256_ecb		= aes + ".41";
	public static final String aes256_cbc		= aes + ".42";
	public static final String aes256_ofb		= aes + ".43";
	public static final String aes256_cfb		= aes + ".44";
	
	
	//for GPKI
	public static final String neat				= "1.2.410.100001.1.7";

/*  Password Based Encryption Algorithm Object Identifier */
	public static final String pbeWithMD5AndDES_CBC		= "1.2.840.113549.1.5.3";
	public static final String pbeWithSHA1AndDESede_CBC	= "1.2.840.113549.1.12.1.3";
	public static final String pbeWithHAS160AndSEED_ECB	= "1.2.410.200004.1.10";
	public static final String pbeWithHAS160AndSEED_CBC	= "1.2.410.200004.1.11";
	public static final String pbeWithHAS160AndSEED_OFB	= "1.2.410.200004.1.12";
	public static final String pbeWithHAS160AndSEED_CFB	= "1.2.410.200004.1.13";
	public static final String pbeWithSHA1AndSEED_ECB	= "1.2.410.200004.1.14";
	public static final String pbeWithSHA1AndSEED_CBC	= "1.2.410.200004.1.15";
	public static final String pbeWithSHA1AndSEED_OFB	= "1.2.410.200004.1.16";
	public static final String pbeWithSHA1AndSEED_CFB	= "1.2.410.200004.1.17";

	public static final String PBES2 					= "1.2.840.113549.1.5.13";

/*  Message Authentication Code Algorithm Object Identifier */
	public static final String seedMac			= "1.2.410.200004.1.7";
	public static final String PasswordBasedMac		= "1.2.840.113533.7.66.13";
	public static final String DHBasedMac			= "1.2.840.113533.7.66.30";

/*  RDN  Object Identifier */
	public static final String country					= "2.5.4.6";
	public static final String locality					= "2.5.4.7";
	public static final String state					= "2.5.4.8";
	public static final String organization				= "2.5.4.10";
	public static final String organizationalUnit		= "2.5.4.11";
	public static final String commonName				= "2.5.4.3";
	public static final String RDN_rsa					= "2.5.4.8.1.1";
	public static final String emailAddress				= "1.2.840.113549.1.9.1";
	
	
	//wolf
	//2004-12-22
	//for TSA
	public static final String TSA_EXT					= "2.5.4.4";
	public static final String id_ct_TSTInfo			= "1.2.840.113549.1.9.16.1.4";
	public static final String id_kp_timeStamping			= "1.3.6.1.5.5.7.3.8";
	
/*  X509 Certificate Extension Field  Object Identiier */
	public static final String oldAuthorityKeyIdentifier	= "2.5.29.1";
	public static final String oldPrimaryKeyATTRIBUTE		= "2.5.29.2";
	public static final String certificatePolicies			= "2.5.29.3";
	public static final String primaryKeyUsageRestriction	= "2.5.29.4";
	public static final String subjectKeyIdentifier			= "2.5.29.14";
	public static final String keyUsage						= "2.5.29.15";
	public static final String privateKeyUsagePeriod 		= "2.5.29.16";
	public static final String subjectAltName				= "2.5.29.17";
	public static final String issuerAltName				= "2.5.29.18";
	public static final String basicConstraints				= "2.5.29.19";
	public static final String crlNumber					= "2.5.29.20";
	public static final String reasonCode					= "2.5.29.21";
	public static final String holdInstructionCode			= "2.5.29.23";
	public static final String invalidityDate				= "2.5.29.24";
	public static final String deltaCRLIndicator			= "2.5.29.27";
	public static final String issuingDistributionPoint		= "2.5.29.28";
	public static final String certificateIssuer			= "2.5.29.29";
	public static final String nameConstraints				= "2.5.29.30";
	public static final String crlDistributionPoint			= "2.5.29.31";
	public static final String certificatePolicy			= "2.5.29.32";
	public static final String policyMapping				= "2.5.29.33";
	public static final String authorityKeyIdentifier		= "2.5.29.35";
	public static final String policyConstraints			= "2.5.29.36";
	public static final String extendedKeyUsage				= "2.5.29.37";
	public static final String netscapeCertType				= "2.16.840.1.113730.1.1";
	public static final String authorityInfoAccess 			= "1.3.6.1.5.5.7.1.1";
	public static final String extKeyUsage 					= "2.5.29.37";
	public static final String inhibitAnyPolicy				= "2.5.29.54";

	public static final String extKeyUsageForOCSP = "1.3.6.1.5.5.7.3.9";
	public static final String id_pkix_id_qt_unotice = "1.3.6.1.5.5.7.2.2";
	public static final String id_pkix_id_qt_cps = "1.3.6.1.5.5.7.2.1";


/*  CMS(PKCS7) Object Identifier */
	public static final String id_data			= "1.2.840.113549.1.7.1";
	public static final String id_signedData		= "1.2.840.113549.1.7.2";
	public static final String id_envelopedData		= "1.2.840.113549.1.7.3";
	public static final String id_signedAndenvelopedData	= "1.2.840.113549.1.7.4";
	public static final String id_digestedData		= "1.2.840.113549.1.7.5";
	public static final String id_encryptedData		= "1.2.840.113549.1.7.6";
	public static final String id_authData			= "1.2.840.113549.1.9.16.1.2";

/*  CMS Attribute(PKCS9) Object Identifier */
	public static final String id_contentType		= "1.2.840.113549.1.9.3";
	public static final String id_messageDigest		= "1.2.840.113549.1.9.4";
	public static final String id_signingTime		= "1.2.840.113549.1.9.5";
	public static final String id_counterSignature		= "1.2.840.113549.1.9.6";
	public static final String id_macValue			= "1.2.840.113549.1.9.16.2.8";
	public static final String smimeCapabilities		= "1.2.840.113549.1.9.15";

	public static final String id_bagTypes			= "1.2.840.113549.1.12.10.1";
	public static final String keyBag			= "1.2.840.113549.1.12.10.1.1";
	public static final String pkcs_8ShroudedKeyBag 	= "1.2.840.113549.1.12.10.1.2";
	public static final String certBag			= "1.2.840.113549.1.12.10.1.3";
	public static final String crlBag			= "1.2.840.113549.1.12.10.1.4";
	public static final String secretBag			= "1.2.840.113549.1.12.10.1.5";
	public static final String safeContentBag		= "1.2.840.113549.1.12.10.1.6";

	public static final String friendlyName			= "1.2.840.113549.1.9.20";
	public static final String localKeyId			= "1.2.840.113549.1.9.21";
	public static final String id_certTypes			= "1.2.840.113549.1.9.22";
	public static final String x509Certificate		= "1.2.840.113549.1.9.22.1";
	public static final String sdsiCertificate		= "1.2.840.113549.1.9.22.2";
	public static final String id_crlTypes			= "1.2.840.113549.1.9.23";
	public static final String x509crl			= "1.2.840.113549.1.0.23.1";

/*  Certified Certifaction Authority Object Identifier */
	public static final String id_signkorea			= "1.2.410.200004.5.1";
	public static final String id_signgate			= "1.2.410.200004.5.2";
	public static final String id_yessign			= "1.2.410.200005";

/*  Add JHJANG For Validate VID */
	public static final String id_npki 			    = "1.2.410.200004.10";
	public static final String id_attribute 		= "1.2.410.200004.10.1";
	public static final String id_kisa_identifyData = "1.2.410.200004.10.1.1";
	public static final String id_VID 			    = "1.2.410.200004.10.1.1.1";
	public static final String id_EncryptedVID 		= "1.2.410.200004.10.1.1.2";
	public static final String id_randomNum 		= "1.2.410.200004.10.1.1.3";


/*	OCSP	*/
	public static final String id_pkix_ocsp 		= "1.3.6.1.5.5.7.48.1";
	public static final String id_pkix_oscp_basic	= "1.3.6.1.5.5.7.48.1.1";
	public static final String id_pkix_oscp_nonce	= "1.3.6.1.5.5.7.48.1.2";
	public static final String id_pkix_oscp_response	= "1.3.6.1.5.5.7.48.1.4";

	private static UpperCaseProperties names;
	private static UpperCaseProperties oids;
	
	//for costarica
	public static final String givenName  = "2.5.4.42";
	public static final String surName = "2.5.4.4";
	public static final String serialNumber  = "2.5.4.5";

	public OID () {}

	static
	{
		names = new UpperCaseProperties ();

		/*  Message Digest */
		names.put(md2, "MD2");
		names.put(md5, "MD5");
		names.put(sha, "SHA");
		names.put(sha1, "SHA1");
		names.put(sha256, "SHA256");
		names.put(sha384, "SHA384");
		names.put(sha512, "SHA512");
		names.put(sha224, "SHA224");
		
		
		names.put(hmacWithSHA1, "HMACwithSHA1");
		names.put(hmacWithSHA224, "HMACwithSHA224");
		names.put(hmacWithSHA256, "HMACwithSHA256");
		names.put(hmacWithSHA384, "HMACwithSHA384");
		names.put(hmacWithSHA512, "HMACwithSHA512");
		
		
		names.put(has160, "HAS160");

		/* Digital Signature */
		names.put(md5WithRSAEncryption, "MD5withRSA");
		names.put(sha1WithRSAEncryption, "SHA1withRSA");
		names.put(sha256WithRSAEncryption, "SHA256withRSA");
		names.put(sha384WithRSAEncryption, "SHA384withRSA");
		names.put(sha512WithRSAEncryption, "SHA512withRSA");
		names.put(has160WithRSAEncryption, "HAS160withRSA");

		names.put(kcdsa, "KCDSA");
		names.put(kcdsa1, "KCDSA1");
		names.put(has160WithKCDSA, "HAS160withKCDSA");
		names.put(sha1WithKCDSA, "SHA1withKCDSA");
		names.put(has160WithKCDSA1, "HAS160withKCDSA1");
		names.put(sha1WithKCDSA1, "SHA1withKCDSA1");
		names.put(has160WithECDSA, "HAS160withECDSA");
		names.put(ECDSA, "ECDSA");

		
		names.put(ecdsaWithSHA1, "SHA1WithECDSA");

		/* Asymmetric Encryption Algorithm */
		names.put(rsaEncryption, "RSA");

		/* Symmetric Encryption Algorithm */
		names.put(des_cbc, "DES/CBC");
		names.put(des_ede_cbc, "DESede/CBC");
		names.put(seed_ecb, "SEED/ECB");
		names.put(seed_cbc, "SEED/CBC");
		names.put(seed_ofb, "SEED/OFB");
		names.put(seed_cfb, "SEED/CFB");
		names.put(aria_cbc, "ARIA/CBC");
		
		names.put(aes128_ecb, "AES/ECB");
		names.put(aes128_cbc, "AES/CBC");
		names.put(aes128_ofb, "AES/OFB");
		names.put(aes128_cfb, "AES/CFB");
		names.put(aes192_ecb, "AES/ECB");
		names.put(aes192_cbc, "AES/CBC");
		names.put(aes192_ofb, "AES/OFB");
		names.put(aes192_cfb, "AES/CFB");
		names.put(aes256_ecb, "AES/ECB");
		names.put(aes256_cbc, "AES/CBC");
		names.put(aes256_ofb, "AES/OFB");
		names.put(aes256_cfb, "AES/CFB");

		names.put(aria128_ecb, "ARIA/ECB");
		names.put(aria128_cbc, "ARIA/CBC");
		names.put(aria128_ofb, "ARIA/OFB");
		names.put(aria128_cfb, "ARIA/CFB");
		names.put(aria128_ctr, "ARIA/CTR");
		names.put(aria192_ecb, "ARIA/ECB");
		names.put(aria192_cbc, "ARIA/CBC");
		names.put(aria192_ofb, "ARIA/OFB");
		names.put(aria192_cfb, "ARIA/CFB");
		names.put(aria192_ctr, "ARIA/CTR");
		names.put(aria256_ecb, "ARIA/ECB");
		names.put(aria256_cbc, "ARIA/CBC");
		names.put(aria256_ofb, "ARIA/OFB");
		names.put(aria256_cfb, "ARIA/CFB");
		names.put(aria256_ctr, "ARIA/CTR");
		

		/* Passpword Based Encryption Algorithm */
		names.put(pbeWithMD5AndDES_CBC, "PBEwithMD5andDES-CBC");
		names.put(pbeWithSHA1AndDESede_CBC, "PBEwithSHA1andDESede-CBC");
		names.put(pbeWithHAS160AndSEED_ECB, "PBEwithHAS160andSEED_ECB");
		names.put(pbeWithHAS160AndSEED_CBC, "PBEwithHAS160andSEED_CBC");
		names.put(pbeWithHAS160AndSEED_OFB, "PBEwithHAS160andSEED_OFB");
		names.put(pbeWithHAS160AndSEED_CFB, "PBEwithHAS160andSEED_CFB");
		names.put(pbeWithSHA1AndSEED_ECB, "PBEwithSHA1andSEED_ECB");
		names.put(pbeWithSHA1AndSEED_CBC, "PBEwithSHA1andSEED_CBC");
		names.put(pbeWithSHA1AndSEED_OFB, "PBEwithSHA1andSEED_OFB");
		names.put(pbeWithSHA1AndSEED_CFB, "PBEwithSHA1andSEED_CFB");

		names.put(PBES2, "PBES2");


		/* RDN */
		names.put(country, "c");
		names.put(state, "st");
		names.put(locality, "l");
		names.put(organization, "o");
		names.put(organizationalUnit, "ou");
		names.put(commonName, "cn");
		names.put(emailAddress, "EmailAddress");
		names.put(RDN_rsa, "RDN_RSA");

		/* PKCS7 */
		names.put(id_data, "pkcs7-data");
		names.put(id_signedData, "pkcs7-signedData");
		names.put(id_envelopedData, "pkcs7-envelopedData");
		names.put(id_signedAndenvelopedData, "pkcs7_signedAndenvelopedData");
		names.put(id_digestedData, "pkcs7-digestedData");
		names.put(id_encryptedData, "pkcs7-encryptedData");

		/* PKCS Attribute */
		names.put(id_contentType, "id-contentType");
		names.put(id_messageDigest, "id-messageDigest");
		names.put(id_signingTime, "id-signingTime");

		/*  Certified Certifaction Authority Object Identifier */
		names.put(id_signkorea, "SIGNKOREA");
		names.put(id_signgate, "SIGNGATE");
		names.put(id_yessign, "YESSIGN");

		/* NPKI VID Validate */
        names.put(id_npki, "id-npki" );
		names.put(id_attribute, "id-attribute" );
		names.put(id_kisa_identifyData, "id-kisa-identifyData" );
		names.put(id_VID, "id-VID" );
		names.put(id_EncryptedVID, "id-EncryptedVID" );
		names.put(id_randomNum, "id-randomNum" );
		
		/* add for costarical dn*/
		names.put(surName, "surName");
		names.put(givenName, "givenName");
		names.put(serialNumber, "serialNumber");

		oids = new UpperCaseProperties();

		/*  Message Digest */
		oids.put("MD2", md2);
		oids.put("MD5", md5);
		oids.put("SHA", sha1);
		oids.put("SHA1", sha1);
		oids.put("SHA224", sha224);
		oids.put("SHA256", sha256);
		oids.put("SHA384", sha384);
		oids.put("SHA512", sha512);
		oids.put("HAS160", has160);
		oids.put("SHA-11", sha1);
		oids.put("SHA-224", sha224);
		oids.put("SHA-256", sha256);
		oids.put("SHA-384", sha384);
		oids.put("SHA-512", sha512);
		oids.put("HAS-160", has160);
		
		
		oids.put("HMACwithSHA1",hmacWithSHA1);
		oids.put("HMACwithSHA224",hmacWithSHA224);
		oids.put("HMACwithSHA256",hmacWithSHA256);
		oids.put("HMACwithSHA384",hmacWithSHA384);
		oids.put("HMACwithSHA512",hmacWithSHA512);

		
		
		/* Digital Signature */
		oids.put("MD5withRSA", md5WithRSAEncryption);
		oids.put("MD5/RSA", md5WithRSAEncryption);
		oids.put("MD5-RSA", md5WithRSAEncryption);
		oids.put("SHA1withRSA", sha1WithRSAEncryption);
		oids.put("SHA1/RSA", sha1WithRSAEncryption);
		oids.put("SHA1-RSA", sha1WithRSAEncryption);
		oids.put("SHA2withRSA", sha256WithRSAEncryption);
		oids.put("SHA2/RSA", sha256WithRSAEncryption);
		oids.put("SHA2-RSA", sha256WithRSAEncryption);
		oids.put("SHA256withRSA", sha256WithRSAEncryption);
		oids.put("SHA384withRSA", sha384WithRSAEncryption);
		oids.put("SHA512withRSA", sha512WithRSAEncryption);
		oids.put("HAS160withKCDSA", has160WithKCDSA);
		oids.put("HAS160/KCDSA", has160WithKCDSA);
		oids.put("HAS160-KCDSA", has160WithKCDSA);
		oids.put("SHA1withKCDSA", sha1WithKCDSA);
		oids.put("SHA1/KCDSA", sha1WithKCDSA);
		oids.put("SHA1-KCDSA", sha1WithKCDSA);
		oids.put("HAS160withRSA", has160WithRSAEncryption);
		oids.put("HAS160/RSA", has160WithRSAEncryption);
		oids.put("HAS160-RSA", has160WithRSAEncryption);
		oids.put("HAS160withKCDSA1", has160WithKCDSA1);
		oids.put("HAS160/KCDSA1", has160WithKCDSA1);
		oids.put("HAS160-KCDSA1", has160WithKCDSA1);
		oids.put("SHA1withKCDSA1", sha1WithKCDSA1);
		oids.put("SHA1/KCDSA1", sha1WithKCDSA1);
		oids.put("SHA1-KCDSA1", sha1WithKCDSA1);
		oids.put("KCDSA", kcdsa);
		oids.put("KCDSA1", kcdsa1);
		oids.put("HAS160withECDSA", has160WithECDSA);
		oids.put("HAS160/ECDSA", has160WithECDSA);
		oids.put("HAS160-ECDSA", has160WithECDSA);


		oids.put("SHA1-ECDSA", ecdsaWithSHA1);
		oids.put("SHA1WithECDSA", ecdsaWithSHA1);

		/* Asymmetric Encryption Algorithm */
		oids.put("RSA", rsaEncryption);

		/*  Symmetric Encryption Algorithm Object Identifier */
		oids.put("DES/CBC", des_cbc);
		oids.put("DESede/CBC", des_ede_cbc);
		oids.put("SEED/ECB", seed_ecb);
		oids.put("SEED/CBC", seed_cbc);
		oids.put("SEED/OFB", seed_ofb);
		oids.put("SEED/CFB", seed_cfb);
		oids.put("ARIA/CBC", aria_cbc);
		

		oids.put("ARIA128/ECB", aria128_ecb);
		oids.put("ARIA128/CBC", aria128_cbc);
		oids.put("ARIA128/OFB", aria128_ofb);
		oids.put("ARIA128/CFB", aria128_cfb);
		oids.put("ARIA192/ECB", aria192_ecb);
		oids.put("ARIA192/CBC", aria192_cbc);
		oids.put("ARIA192/OFB", aria192_ofb);
		oids.put("ARIA192/CFB", aria192_cfb);
		oids.put("ARIA256/ECB", aria256_ecb);
		oids.put("ARIA256/CBC", aria256_cbc);
		oids.put("ARIA256/OFB", aria256_ofb);
		oids.put("ARIA256/CFB", aria256_cfb);
	

		oids.put("AES128/ECB", aes128_ecb);
		oids.put("AES128/CBC", aes128_cbc);
		oids.put("AES128/OFB", aes128_ofb);
		oids.put("AES128/CFB", aes128_cfb);
		oids.put("AES192/ECB", aes192_ecb);
		oids.put("AES192/CBC", aes192_cbc);
		oids.put("AES192/OFB", aes192_ofb);
		oids.put("AES192/CFB", aes192_cfb);
		oids.put("AES256/ECB", aes256_ecb);
		oids.put("AES256/CBC", aes256_cbc);
		oids.put("AES256/OFB", aes256_ofb);
		oids.put("AES256/CFB", aes256_cfb);
		

		/* Passpword Based Encryption Algorithm */
		oids.put("PBEwithMD5andDES-CBC", pbeWithMD5AndDES_CBC);
		oids.put("PBEwithSHA1andDESede-CBC", pbeWithSHA1AndDESede_CBC);
		oids.put("PBEwithHAS160andSEED_ECB", pbeWithHAS160AndSEED_ECB);
		oids.put("PBEwithHAS160andSEED_CBC", pbeWithHAS160AndSEED_CBC);
		oids.put("PBEwithHAS160andSEED_OFB", pbeWithHAS160AndSEED_OFB);
		oids.put("PBEwithHAS160andSEED_CFB", pbeWithHAS160AndSEED_CFB);
		oids.put("PBEwithSHA1andSEED_ECB", pbeWithSHA1AndSEED_ECB);
		oids.put("PBEwithSHA1andSEED_CBC", pbeWithSHA1AndSEED_CBC);
		oids.put("PBEwithSHA1andSEED_OFB", pbeWithSHA1AndSEED_OFB);
		oids.put("PBEwithSHA1andSEED_CFB", pbeWithSHA1AndSEED_CFB);

		oids.put("PBES2", PBES2);

		/* RDN */
		oids.put("c", country);
		oids.put("st", state);
		oids.put("l", locality);
		oids.put("o", organization);
		oids.put("ou", organizationalUnit);
		oids.put("cn", commonName);
		oids.put("EmailAddress", emailAddress);
		oids.put("RDN_RSA", RDN_rsa);

		/* PKCS7 */
		oids.put("pkcs7-data", id_data);
		oids.put("pkcs7-signedData", id_signedData);
		oids.put("pkcs7-envelopedData", id_envelopedData);
		oids.put("pkcs7_signedAndenvelopedData", id_signedAndenvelopedData);
		oids.put("pkcs7-digestedData", id_digestedData);
		oids.put("pkcs7-encryptedData", id_encryptedData);

		/* PKCS Attribute */
		oids.put("id-contentType", id_contentType);
		oids.put("id-messageDigest", id_messageDigest);
		oids.put("id-signingTime", id_signingTime);

		/* NPKI VID Validate */
		oids.put("id-npki", id_npki );
		oids.put("id-attribute", id_attribute );
		oids.put("id-kisa-identifyData", id_kisa_identifyData );
		oids.put("id-VID", id_VID );
		oids.put("id-EncryptedVID", id_EncryptedVID );
		oids.put("id-randomNum", id_randomNum );
		
		//for TSA
		oids.put("id_ct_TSTInfo", id_ct_TSTInfo);
		oids.put("id_kp_timeStamp", id_kp_timeStamping);
		
		/* add for costarical dn*/
		oids.put("surName", surName);
		oids.put("givenName", givenName);
		oids.put("serialNumber", serialNumber);
		
	}

	public static final String getAlgName(String oid)
	{
		return (String)names.get(oid);
	}

	public static final String getAlgOid(String name)
	{
		return (String)oids.get(name);
	}

	public static final String getAlgOid(String name,int keyLength)
	{
		// if it can find the algorithm OID by name, it should be returned. 
		String oid = getAlgOid(name);
		if (oid != null)
			return oid; 
		
		StringBuffer buffer = new StringBuffer();
		StringTokenizer st = new StringTokenizer(name,"/");
		
		buffer.append(st.nextToken());
		buffer.append(keyLength * 8);
		if (st.hasMoreTokens())
			buffer.append("/").append(st.nextToken());

		return getAlgOid(buffer.toString());
	}
	
	
	static class UpperCaseProperties extends Properties
	{
		public UpperCaseProperties()
		{
			super();
		}
		
	    public synchronized Object put(Object key, Object value) {
			return super.put(toUpper(key),value);
		}
	    
	    public synchronized Object get(Object key) {
	    	return super.get(toUpper(key));
	    }
	    
	    public synchronized Object setProperty(String key, String value) {
	    	return super.setProperty((String)toUpper(key), value);
	    }
	    
	    public String getProperty(String key) {
	    	return super.getProperty((String)toUpper(key));
	   }
	    
	    Object toUpper(Object key)
	    {
	    	return (key instanceof String) ? ((String)key).toUpperCase() : key;
	    }
	}
}
