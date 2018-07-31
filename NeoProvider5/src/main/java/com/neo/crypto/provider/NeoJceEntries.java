/*
 * Copyright (c) 1996, 2006, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.neo.crypto.provider;

import java.security.SecureRandom;
import java.util.Map;


final public class NeoJceEntries {

	private NeoJceEntries() {
		// empty
	}

	public static final String PROVIDER_NAME = "NEO";

	private static final long serialVersionUID = 992576281378203529L;

	private static final String info = "NeoJCE Provider " +
			"(implements RSA, SEED, ARIA, DES, Triple DES, AES, Blowfish, ARCFOUR, RC2, PBE, "
			+ "Diffie-Hellman, HMAC)";

	private static final String OID_PKCS12_RC2_40 = "1.2.840.113549.1.12.1.6";
	private static final String OID_PKCS12_DESede = "1.2.840.113549.1.12.1.3";
	private static final String OID_PKCS5_MD5_DES = "1.2.840.113549.1.5.3";
	private static final String OID_PKCS5_PBKDF2 = "1.2.840.113549.1.5.12";
	private static final String OID_PKCS3 = "1.2.840.113549.1.3.1";

	/* Are we debugging? -- for developers */
	static final boolean debug = false;

	static final SecureRandom RANDOM = new SecureRandom();

	public static void putEntries(Map<Object, Object> map) {

		final String BLOCK_MODES = "ECB|CBC|PCBC|CTR|CTS|CFB|OFB" +
				"|CFB8|CFB16|CFB24|CFB32|CFB40|CFB48|CFB56|CFB64" +
				"|OFB8|OFB16|OFB24|OFB32|OFB40|OFB48|OFB56|OFB64";
		final String BLOCK_MODES128 = BLOCK_MODES +
				"|CFB72|CFB80|CFB88|CFB96|CFB104|CFB112|CFB120|CFB128" +
				"|OFB72|OFB80|OFB88|OFB96|OFB104|OFB112|OFB120|OFB128";
		final String BLOCK_PADS = "NOPADDING|PKCS5PADDING|ISO10126PADDING";

		/*
		 * Cipher engines
		 */
		map.put("Cipher.RSA", "com.neo.crypto.provider.RSACipher");
		map.put("Cipher.RSA SupportedModes", "ECB");
		map.put("Cipher.RSA SupportedPaddings",
				"NOPADDING|PKCS1PADDING|OAEPWITHMD5ANDMGF1PADDING"
						+ "|OAEPWITHSHA1ANDMGF1PADDING"
						+ "|OAEPWITHSHA-1ANDMGF1PADDING"
						+ "|OAEPWITHSHA-256ANDMGF1PADDING"
						+ "|OAEPWITHSHA-384ANDMGF1PADDING"
						+ "|OAEPWITHSHA-512ANDMGF1PADDING");
		map.put("Cipher.RSA SupportedKeyClasses",
				"java.security.interfaces.RSAPublicKey" +
				"|java.security.interfaces.RSAPrivateKey");

		map.put("Cipher.DES", "com.neo.crypto.provider.DESCipher");
		map.put("Cipher.DES SupportedModes", BLOCK_MODES);
		map.put("Cipher.DES SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.DES SupportedKeyFormats", "RAW");

		map.put("Cipher.DESede", "com.neo.crypto.provider.DESedeCipher");
		map.put("Alg.Alias.Cipher.TripleDES", "DESede");
		map.put("Cipher.DESede SupportedModes", BLOCK_MODES);
		map.put("Cipher.DESede SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.DESede SupportedKeyFormats", "RAW");

		map.put("Cipher.DESedeWrap",
				"com.neo.crypto.provider.DESedeWrapCipher");
		map.put("Cipher.DESedeWrap SupportedModes", "CBC");
		map.put("Cipher.DESedeWrap SupportedPaddings", "NOPADDING");
		map.put("Cipher.DESedeWrap SupportedKeyFormats", "RAW");


		// Standard PBEWithSHA1AndSEED Algorithm
		map.put("Cipher.PBEWithSHA1AndSEED",
				"com.neo.crypto.provider.PBEWithSHA1AndSEEDCipher");
		map.put("Alg.Alias.Cipher.OID."+ "1.2.410.200004.1.15",
				"PBEWithSHA1AndSEED");

		// Non Standard PBEWithSHA1AndSEED Algorithm, a fixed IV is used.
		map.put("Cipher.PBEWithSHA1AndSEED2",
				"com.neo.crypto.provider.PBEWithSHA1AndSEEDCipherNoIV");
		map.put("Alg.Alias.Cipher.OID."+ "1.2.410.200004.1.4.2",
				"PBEWithSHA1AndSEED2");

		map.put("Cipher.PBEWithMD5AndDES",
				"com.neo.crypto.provider.PBEWithMD5AndDESCipher");
		map.put("Alg.Alias.Cipher.OID."+OID_PKCS5_MD5_DES,
				"PBEWithMD5AndDES");
		map.put("Alg.Alias.Cipher."+OID_PKCS5_MD5_DES,
				"PBEWithMD5AndDES");
		map.put("Cipher.PBEWithMD5AndTripleDES",
				"com.neo.crypto.provider.PBEWithMD5AndTripleDESCipher");
		map.put("Cipher.PBEWithSHA1AndRC2_40",
				"com.neo.crypto.provider.PKCS12PBECipherCore$" +
				"PBEWithSHA1AndRC2_40");
		map.put("Alg.Alias.Cipher.OID." + OID_PKCS12_RC2_40,
				"PBEWithSHA1AndRC2_40");
		map.put("Alg.Alias.Cipher." + OID_PKCS12_RC2_40,
				"PBEWithSHA1AndRC2_40");
		map.put("Cipher.PBEWithSHA1AndDESede",
				"com.neo.crypto.provider.PKCS12PBECipherCore$" +
				"PBEWithSHA1AndDESede");
		map.put("Alg.Alias.Cipher.OID." + OID_PKCS12_DESede,
				"PBEWithSHA1AndDESede");
		map.put("Alg.Alias.Cipher." + OID_PKCS12_DESede,
				"PBEWithSHA1AndDESede");

		map.put("Cipher.Blowfish",
				"com.neo.crypto.provider.BlowfishCipher");
		map.put("Cipher.Blowfish SupportedModes", BLOCK_MODES);
		map.put("Cipher.Blowfish SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.Blowfish SupportedKeyFormats", "RAW");

		map.put("Cipher.AES", "com.neo.crypto.provider.AESCipher");
		map.put("Alg.Alias.Cipher.Rijndael", "AES");
		map.put("Cipher.AES SupportedModes", BLOCK_MODES128);
		map.put("Cipher.AES SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.AES SupportedKeyFormats", "RAW");

		map.put("Cipher.AESWrap", "com.neo.crypto.provider.AESWrapCipher");
		map.put("Cipher.AESWrap SupportedModes", "ECB");
		map.put("Cipher.AESWrap SupportedPaddings", "NOPADDING");
		map.put("Cipher.AESWrap SupportedKeyFormats", "RAW");

		map.put("Cipher.RC2",
				"com.neo.crypto.provider.RC2Cipher");
		map.put("Cipher.RC2 SupportedModes", BLOCK_MODES);
		map.put("Cipher.RC2 SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.RC2 SupportedKeyFormats", "RAW");

		map.put("Cipher.ARCFOUR",
				"com.neo.crypto.provider.ARCFOURCipher");
		map.put("Alg.Alias.Cipher.RC4", "ARCFOUR");
		map.put("Cipher.ARCFOUR SupportedModes", "ECB");
		map.put("Cipher.ARCFOUR SupportedPaddings", "NOPADDING");
		map.put("Cipher.ARCFOUR SupportedKeyFormats", "RAW");


		map.put("Cipher.SEED",
				"com.neo.crypto.provider.SEEDCipher");
		map.put("Cipher.SEED SupportedModes", BLOCK_MODES);
		map.put("Cipher.SEED SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.SEED SupportedKeyFormats", "RAW");

		map.put("Cipher.ARIA",
				"com.neo.crypto.provider.ARIACipher");
		map.put("Cipher.ARIA SupportedModes", BLOCK_MODES128);
		map.put("Cipher.ARIA SupportedPaddings", BLOCK_PADS);
		map.put("Cipher.ARIA SupportedKeyFormats", "RAW");

		
		/*
		 *  Key(pair) Generator engines
		 */
		map.put("KeyGenerator.DES",
				"com.neo.crypto.provider.DESKeyGenerator");

		map.put("KeyGenerator.DESede",
				"com.neo.crypto.provider.DESedeKeyGenerator");
		map.put("Alg.Alias.KeyGenerator.TripleDES", "DESede");

		map.put("KeyGenerator.Blowfish",
				"com.neo.crypto.provider.BlowfishKeyGenerator");

		map.put("KeyGenerator.AES",
				"com.neo.crypto.provider.AESKeyGenerator");
		map.put("Alg.Alias.KeyGenerator.Rijndael", "AES");

		map.put("KeyGenerator.RC2",
				"com.neo.crypto.provider.KeyGeneratorCore$" +
				"RC2KeyGenerator");
		map.put("KeyGenerator.ARCFOUR",
				"com.neo.crypto.provider.KeyGeneratorCore$" +
				"ARCFOURKeyGenerator");
		map.put("Alg.Alias.KeyGenerator.RC4", "ARCFOUR");

		map.put("KeyGenerator.SEED",
				"com.neo.crypto.provider.SEEDKeyGenerator");

		map.put("KeyGenerator.ARIA",
				"com.neo.crypto.provider.ARIAKeyGenerator");

		
		map.put("KeyGenerator.HmacMD5",
				"com.neo.crypto.provider.HmacMD5KeyGenerator");

		map.put("KeyGenerator.HmacSHA1",
				"com.neo.crypto.provider.HmacSHA1KeyGenerator");

		map.put("KeyGenerator.HmacSHA256",
				"com.neo.crypto.provider.KeyGeneratorCore$HmacSHA256KG");
		map.put("KeyGenerator.HmacSHA384",
				"com.neo.crypto.provider.KeyGeneratorCore$HmacSHA384KG");
		map.put("KeyGenerator.HmacSHA512",
				"com.neo.crypto.provider.KeyGeneratorCore$HmacSHA512KG");

		map.put("KeyPairGenerator.DiffieHellman",
				"com.neo.crypto.provider.DHKeyPairGenerator");
		map.put("Alg.Alias.KeyPairGenerator.DH", "DiffieHellman");
		map.put("Alg.Alias.KeyPairGenerator.OID."+OID_PKCS3,
				"DiffieHellman");
		map.put("Alg.Alias.KeyPairGenerator."+OID_PKCS3,
				"DiffieHellman");
		/*
		 * Algorithm parameter generation engines
		 */
		map.put("AlgorithmParameterGenerator.DiffieHellman",
				"com.neo.crypto.provider.DHParameterGenerator");
		map.put("Alg.Alias.AlgorithmParameterGenerator.DH",
				"DiffieHellman");
		map.put("Alg.Alias.AlgorithmParameterGenerator.OID."+OID_PKCS3,
				"DiffieHellman");
		map.put("Alg.Alias.AlgorithmParameterGenerator."+OID_PKCS3,
				"DiffieHellman");

		/*
		 * Key Agreement engines
		 */
		map.put("KeyAgreement.DiffieHellman",
				"com.neo.crypto.provider.DHKeyAgreement");
		map.put("Alg.Alias.KeyAgreement.DH", "DiffieHellman");
		map.put("Alg.Alias.KeyAgreement.OID."+OID_PKCS3, "DiffieHellman");
		map.put("Alg.Alias.KeyAgreement."+OID_PKCS3, "DiffieHellman");

		map.put("KeyAgreement.DiffieHellman SupportedKeyClasses",
				"javax.crypto.interfaces.DHPublicKey" +
				"|javax.crypto.interfaces.DHPrivateKey");

		/*
		 * Algorithm Parameter engines
		 */
		map.put("AlgorithmParameters.DiffieHellman",
				"com.neo.crypto.provider.DHParameters");
		map.put("Alg.Alias.AlgorithmParameters.DH", "DiffieHellman");
		map.put("Alg.Alias.AlgorithmParameters.OID."+OID_PKCS3,
				"DiffieHellman");
		map.put("Alg.Alias.AlgorithmParameters."+OID_PKCS3,
				"DiffieHellman");

		map.put("AlgorithmParameters.DES",
				"com.neo.crypto.provider.DESParameters");

		map.put("AlgorithmParameters.DESede",
				"com.neo.crypto.provider.DESedeParameters");
		map.put("Alg.Alias.AlgorithmParameters.TripleDES", "DESede");

		map.put("AlgorithmParameters.PBE",
				"com.neo.crypto.provider.PBEParameters");

		map.put("AlgorithmParameters.PBEWithMD5AndDES",
				"com.neo.crypto.provider.PBEParameters");
		map.put("Alg.Alias.AlgorithmParameters.OID."+OID_PKCS5_MD5_DES,
				"PBEWithMD5AndDES");
		map.put("Alg.Alias.AlgorithmParameters."+OID_PKCS5_MD5_DES,
				"PBEWithMD5AndDES");

		map.put("AlgorithmParameters.PBEWithMD5AndTripleDES",
				"com.neo.crypto.provider.PBEParameters");

		map.put("AlgorithmParameters.PBEWithSHA1AndDESede",
				"com.neo.crypto.provider.PBEParameters");
		map.put("Alg.Alias.AlgorithmParameters.OID."+OID_PKCS12_DESede,
				"PBEWithSHA1AndDESede");
		map.put("Alg.Alias.AlgorithmParameters."+OID_PKCS12_DESede,
				"PBEWithSHA1AndDESede");

		map.put("AlgorithmParameters.PBEWithSHA1AndRC2_40",
				"com.neo.crypto.provider.PBEParameters");
		map.put("Alg.Alias.AlgorithmParameters.OID."+OID_PKCS12_RC2_40,
				"PBEWithSHA1AndRC2_40");
		map.put("Alg.Alias.AlgorithmParameters." + OID_PKCS12_RC2_40,
				"PBEWithSHA1AndRC2_40");

		map.put("AlgorithmParameters.Blowfish",
				"com.neo.crypto.provider.BlowfishParameters");

		map.put("AlgorithmParameters.AES",
				"com.neo.crypto.provider.AESParameters");
		map.put("Alg.Alias.AlgorithmParameters.Rijndael", "AES");


		map.put("AlgorithmParameters.RC2",
				"com.neo.crypto.provider.RC2Parameters");

		map.put("AlgorithmParameters.OAEP",
				"com.neo.crypto.provider.OAEPParameters");

		map.put("AlgorithmParameters.SEED",
				"com.neo.crypto.provider.SEEDParameters");


		/*
		 * Key factories
		 */
		map.put("KeyFactory.DiffieHellman",
				"com.neo.crypto.provider.DHKeyFactory");
		map.put("Alg.Alias.KeyFactory.DH", "DiffieHellman");
		map.put("Alg.Alias.KeyFactory.OID."+OID_PKCS3,
				"DiffieHellman");
		map.put("Alg.Alias.KeyFactory."+OID_PKCS3, "DiffieHellman");
		/*
		 * Secret-key factories
		 */
		map.put("SecretKeyFactory.DES",
				"com.neo.crypto.provider.DESKeyFactory");

		map.put("SecretKeyFactory.DESede",
				"com.neo.crypto.provider.DESedeKeyFactory");
		map.put("Alg.Alias.SecretKeyFactory.TripleDES", "DESede");

		map.put("SecretKeyFactory.PBEWithMD5AndDES",
				"com.neo.crypto.provider.PBEKeyFactory$PBEWithMD5AndDES"
				);
		map.put("Alg.Alias.SecretKeyFactory.OID."+OID_PKCS5_MD5_DES,
				"PBEWithMD5AndDES");
		map.put("Alg.Alias.SecretKeyFactory."+OID_PKCS5_MD5_DES,
				"PBEWithMD5AndDES");

		map.put("Alg.Alias.SecretKeyFactory.PBE",
				"PBEWithMD5AndDES");

		map.put("SecretKeyFactory.PBEWithSHA1AndSEED",
				"com.neo.crypto.provider.PBEKeyFactory$PBEWithSHA1AndSEED");
		map.put("Alg.Alias.SecretKeyFactory.OID."+"1.2.410.200004.1.15",
				"PBEWithSHA1AndSEED");

		map.put("SecretKeyFactory.SEED",
				"com.neo.crypto.provider.SEEDKeyFactory");

		map.put("SecretKeyFactory.ARIA",
				"com.neo.crypto.provider.ARIAKeyFactory");

		map.put("SecretKeyFactory.AES",
				"com.neo.crypto.provider.AESKeyFactory");


		/*
		 * Internal in-house crypto algorithm used for
		 * the JCEKS keystore type.  Since this was developed
		 * internally, there isn't an OID corresponding to this
		 * algorithm.
		 */
		map.put("SecretKeyFactory.PBEWithMD5AndTripleDES",
				"com.neo.crypto.provider.PBEKeyFactory$" +
						"PBEWithMD5AndTripleDES"
				);

		map.put("SecretKeyFactory.PBEWithSHA1AndDESede",
				"com.neo.crypto.provider.PBEKeyFactory$PBEWithSHA1AndDESede"
				);
		map.put("Alg.Alias.SecretKeyFactory.OID."+OID_PKCS12_DESede,
				"PBEWithSHA1AndDESede");
		map.put("Alg.Alias.SecretKeyFactory." + OID_PKCS12_DESede,
				"PBEWithSHA1AndDESede");

		map.put("SecretKeyFactory.PBEWithSHA1AndRC2_40",
				"com.neo.crypto.provider.PBEKeyFactory$PBEWithSHA1AndRC2_40"
				);
		map.put("Alg.Alias.SecretKeyFactory.OID." + OID_PKCS12_RC2_40,
				"PBEWithSHA1AndRC2_40");
		map.put("Alg.Alias.SecretKeyFactory." + OID_PKCS12_RC2_40,
				"PBEWithSHA1AndRC2_40");

		map.put("SecretKeyFactory.PBKDF2WithHmacSHA1",
				"com.neo.crypto.provider.PBKDF2HmacSHA1Factory");
		map.put("Alg.Alias.SecretKeyFactory.OID." + OID_PKCS5_PBKDF2,
				"PBKDF2WithHmacSHA1");
		map.put("Alg.Alias.SecretKeyFactory." + OID_PKCS5_PBKDF2,
				"PBKDF2WithHmacSHA1");

		/*
		 * MAC
		 */
		map.put("Mac.HmacMD5", "com.neo.crypto.provider.HmacMD5");
		map.put("Mac.HmacSHA1", "com.neo.crypto.provider.HmacSHA1");
		map.put("Alg.Alias.Mac.HMACwithSHA1", "HmacSHA1");
		
		map.put("Mac.HmacSHA256",
				"com.neo.crypto.provider.HmacCore$HmacSHA256");
		map.put("Alg.Alias.Mac.HMACwithSHA256", "HmacSHA256");
		
		map.put("Mac.HmacSHA384",
				"com.neo.crypto.provider.HmacCore$HmacSHA384");
		map.put("Alg.Alias.Mac.HMACwithSHA384", "HmacSHA384");
		
		map.put("Mac.HmacSHA512",
				"com.neo.crypto.provider.HmacCore$HmacSHA512");
		map.put("Alg.Alias.Mac.HMACwithSHA512", "HmacSHA512");
		map.put("Mac.HmacPBESHA1",
				"com.neo.crypto.provider.HmacPKCS12PBESHA1");

		map.put("Mac.HmacMD5 SupportedKeyFormats", "RAW");
		map.put("Mac.HmacSHA1 SupportedKeyFormats", "RAW");
		map.put("Mac.HmacSHA256 SupportedKeyFormats", "RAW");
		map.put("Mac.HmacSHA384 SupportedKeyFormats", "RAW");
		map.put("Mac.HmacSHA512 SupportedKeyFormats", "RAW");
		map.put("Mac.HmacPBESHA1 SupportedKeyFormats", "RAW");

		/*
		 * KeyStore
		 */
		map.put("KeyStore.JCEKS", "com.neo.crypto.provider.JceKeyStore");

	}
}
