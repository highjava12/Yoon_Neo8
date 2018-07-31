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

package com.neo.security.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Map;

/**
 * Defines the entries of the NEO provider.
 *
 * Algorithms supported, and their names:
 *
 * - SHA is the message digest scheme described in FIPS 180-1.
 *   Aliases for SHA are SHA-1 and SHA1.
 *
 * - SHA1withDSA is the signature scheme described in FIPS 186.
 *   (SHA used in DSA is SHA-1: FIPS 186 with Change No 1.)
 *   Aliases for SHA1withDSA are DSA, DSS, SHA/DSA, SHA-1/DSA, SHA1/DSA,
 *   SHAwithDSA, DSAWithSHA1, and the object
 *   identifier strings "OID.1.3.14.3.2.13", "OID.1.3.14.3.2.27" and
 *   "OID.1.2.840.10040.4.3".
 *
 * - DSA is the key generation scheme as described in FIPS 186.
 *   Aliases for DSA include the OID strings "OID.1.3.14.3.2.12"
 *   and "OID.1.2.840.10040.4.1".
 *
 * - MD5 is the message digest scheme described in RFC 1321.
 *   There are no aliases for MD5.
 *
 * - X.509 is the certificate factory type for X.509 certificates
 *   and CRLs. Aliases for X.509 are X509.
 *
 * - PKIX is the certification path validation algorithm described
 *   in RFC 3280. The ValidationAlgorithm attribute notes the
 *   specification that this provider implements.
 *
 * - LDAP is the CertStore type for LDAP repositories. The
 *   LDAPSchema attribute notes the specification defining the
 *   schema that this provider uses to find certificates and CRLs.
 *
 * - JavaPolicy is the default file-based Policy type.
 *
 * - JavaLoginConfig is the default file-based LoginModule Configuration type.
 */

final class NeoEntries {

    private NeoEntries() {
        // empty
    }

    static void putEntries(Map<Object, Object> map) {

        /*
         * SecureRandom
         *
         * Register these first to speed up "new SecureRandom()",
         * which iterates through the list of algorithms
         */
        // register the native PRNG, if available
        // if user selected /dev/urandom, we put it before SHA1PRNG,
        // otherwise after it
        boolean nativeAvailable = false;
        boolean useUrandom = seedSource.equals(URL_DEV_URANDOM);
        if (nativeAvailable && useUrandom) {
            map.put("SecureRandom.NativePRNG",
                "com.neo.security.provider.NativePRNG");
        }
        map.put("SecureRandom.SHA1PRNG",
             "com.neo.security.provider.SecureRandom");
        if (nativeAvailable && !useUrandom) {
            map.put("SecureRandom.NativePRNG",
                "com.neo.security.provider.NativePRNG");
        }

        
        //
        // X509Store
        //
        map.put("X509Store.CERTIFICATE/COLLECTION", "com.neo.security.certpath.store.X509StoreCertCollection");
        map.put("X509Store.CRL/COLLECTION", "com.neo.security.certpath.store.X509StoreCRLCollection");

        map.put("X509Store.CERTIFICATE/LDAP", "com.neo.security.certpath.store.X509StoreLDAPCerts");
        map.put("X509Store.CRL/LDAP", "com.neo.security.certpath.store.X509StoreLDAPCRLs");
        map.put("X509Store.CRL/HTTP", "com.neo.security.certpath.store.X509StoreHTTPCRLs");
        
        map.put("X509Store.LDAP", "com.neo.security.certpath.store.X509StoreLDAP");
        map.put("X509Store.CACHE", "com.neo.security.certpath.store.X509StoreDirectory");

        

        /*
         * Signature engines
         */
//        map.put("Signature.SHA1withDSA", "com.neo.security.provider.DSA$SHA1withDSA");
//        map.put("Signature.NONEwithDSA", "com.neo.security.provider.DSA$RawDSA");
//        map.put("Alg.Alias.Signature.RawDSA", "NONEwithDSA");

//        String dsaKeyClasses = "java.security.interfaces.DSAPublicKey" +
//                "|java.security.interfaces.DSAPrivateKey";
//        map.put("Signature.SHA1withDSA SupportedKeyClasses", dsaKeyClasses);
//        map.put("Signature.NONEwithDSA SupportedKeyClasses", dsaKeyClasses);

//        map.put("Alg.Alias.Signature.DSA", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.DSS", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.SHA/DSA", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.SHA-1/DSA", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.SHA1/DSA", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.SHAwithDSA", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.DSAWithSHA1", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.OID.1.2.840.10040.4.3",
//            "SHA1withDSA");
//        map.put("Alg.Alias.Signature.1.2.840.10040.4.3", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.1.3.14.3.2.13", "SHA1withDSA");
//        map.put("Alg.Alias.Signature.1.3.14.3.2.27", "SHA1withDSA");

        /*
         *  Key Pair Generator engines
         */
//        map.put("KeyPairGenerator.DSA",
//            "com.neo.security.provider.DSAKeyPairGenerator");
//        map.put("Alg.Alias.KeyPairGenerator.OID.1.2.840.10040.4.1", "DSA");
//        map.put("Alg.Alias.KeyPairGenerator.1.2.840.10040.4.1", "DSA");
//        map.put("Alg.Alias.KeyPairGenerator.1.3.14.3.2.12", "DSA");

        /*
         * Digest engines
         */
        map.put("MessageDigest.MD2", "com.neo.security.provider.digest.JDKMessageDigest$MD2");
        map.put("MessageDigest.MD5", "com.neo.security.provider.digest.JDKMessageDigest$MD5");

        map.put("MessageDigest.SHA-1", "com.neo.security.provider.digest.JDKMessageDigest$SHA1");
        map.put("Alg.Alias.MessageDigest.SHA", "SHA-1");
        map.put("Alg.Alias.MessageDigest.SHA1", "SHA-1");

        map.put("MessageDigest.SHA-256", "com.neo.security.provider.digest.JDKMessageDigest$SHA256");
        map.put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        
        map.put("MessageDigest.SHA-384", "com.neo.security.provider.digest.JDKMessageDigest$SHA384");
        map.put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        map.put("MessageDigest.SHA-512", "com.neo.security.provider.digest.JDKMessageDigest$SHA512");
        map.put("Alg.Alias.MessageDigest.SHA512", "SHA-512");

        /*
         * Algorithm Parameter Generator engines
         */
//        map.put("AlgorithmParameterGenerator.DSA",
//            "com.neo.security.provider.DSAParameterGenerator");

        /*
         * Algorithm Parameter engines
         */
//        map.put("AlgorithmParameters.DSA",
//            "com.neo.security.provider.DSAParameters");
//        map.put("Alg.Alias.AlgorithmParameters.1.3.14.3.2.12", "DSA");
//        map.put("Alg.Alias.AlgorithmParameters.1.2.840.10040.4.1", "DSA");

        /*
         * Key factories
         */
//        map.put("KeyFactory.DSA", "com.neo.security.provider.DSAKeyFactory");
//        map.put("Alg.Alias.KeyFactory.1.3.14.3.2.12", "DSA");
//        map.put("Alg.Alias.KeyFactory.1.2.840.10040.4.1", "DSA");

        /*
         * Certificates
         */
        map.put("CertificateFactory.X.509", "com.neo.security.provider.X509CertificateFactory");
        map.put("Alg.Alias.CertificateFactory.X509", "X.509");

        /*
         * KeyStore
         */
        map.put("KeyStore.JKS", "com.neo.security.provider.JavaKeyStore$JKS");
        map.put("KeyStore.CaseExactJKS",
                        "com.neo.security.provider.JavaKeyStore$CaseExactJKS");

        /*
         * Policy
         */
//        map.put("Policy.JavaPolicy", "com.neo.security.provider.PolicySpiFile");

        /*
         * Configuration
         */
        map.put("Configuration.JavaLoginConfig",
                        "com.neo.security.provider.ConfigSpiFile");

        /*
         * CertPathBuilder
         */
        map.put("CertPathBuilder.PKIX",
            "com.neo.security.certpath.PKIXCertPathBuilderSpi");
        map.put("CertPathBuilder.PKIX ValidationAlgorithm",
            "RFC3280");

        /*
         * CertPathValidator
         */
        map.put("CertPathValidator.PKIX",
            "com.neo.security.certpath.PKIXCertPathValidatorSpi");
        map.put("CertPathValidator.PKIX ValidationAlgorithm",
            "RFC3280");

        /*
         * CertStores
         */
        map.put("CertStore.Collection", "com.neo.security.certpath.CertStoreCollectionSpi");
        map.put("CertStore.LDAP", "com.neo.security.certpath.X509LDAPCertStoreSpi");
        map.put("CertStore.Multi", "com.neo.security.certpath.MultiCertStoreSpi");
        map.put("Alg.Alias.CertStore.X509LDAP", "LDAP");
        
        /*
         * Implementation type: software or hardware
         */
        map.put("Signature.SHA1withDSA ImplementedIn", "Software");
        map.put("KeyPairGenerator.DSA ImplementedIn", "Software");
        map.put("MessageDigest.MD5 ImplementedIn", "Software");
        map.put("MessageDigest.SHA ImplementedIn", "Software");
        map.put("AlgorithmParameterGenerator.DSA ImplementedIn",
            "Software");
        map.put("AlgorithmParameters.DSA ImplementedIn", "Software");
        map.put("KeyFactory.DSA ImplementedIn", "Software");
        map.put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
        map.put("CertificateFactory.X.509 ImplementedIn", "Software");
        map.put("KeyStore.JKS ImplementedIn", "Software");
        map.put("CertPathValidator.PKIX ImplementedIn", "Software");
        map.put("CertPathBuilder.PKIX ImplementedIn", "Software");
        map.put("CertStore.LDAP ImplementedIn", "Software");
        map.put("CertStore.Collection ImplementedIn", "Software");
        map.put("CertStore.com.neo.security.IndexedCollection ImplementedIn",
            "Software");

    }

    // name of the *System* property, takes precedence over PROP_RNDSOURCE
    private final static String PROP_EGD = "java.security.egd";
    // name of the *Security* property
    private final static String PROP_RNDSOURCE = "securerandom.source";

    final static String URL_DEV_RANDOM = "file:/dev/random";
    final static String URL_DEV_URANDOM = "file:/dev/urandom";

    private static final String seedSource;

    static {
        seedSource = AccessController.doPrivileged(
                new PrivilegedAction<String>() {

            public String run() {
                String egdSource = System.getProperty(PROP_EGD, "");
                if (egdSource.length() != 0) {
                    return egdSource;
                }
                egdSource = Security.getProperty(PROP_RNDSOURCE);
                if (egdSource == null) {
                    return "";
                }
                return egdSource;
            }
        });
    }

    static String getSeedSource() {
        return seedSource;
    }

}
