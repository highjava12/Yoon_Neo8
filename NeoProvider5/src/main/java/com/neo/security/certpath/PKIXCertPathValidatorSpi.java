package com.neo.security.certpath;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import com.neo.security.asn1.DEREncodable;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.x509.AlgorithmIdentifier;
import com.neo.security.x509.ExtendedPKIXParameters;

/**
 * CertPathValidatorSpi implementation for X.509 Certificate validation � la RFC
 * 3280.
 */
public class PKIXCertPathValidatorSpi
        extends CertPathValidatorSpi
{

    public CertPathValidatorResult engineValidate(
            CertPath certPath,
            CertPathParameters params)
            throws CertPathValidatorException,
            InvalidAlgorithmParameterException
    {
        if (!(params instanceof PKIXParameters))
        {
            throw new InvalidAlgorithmParameterException("Parameters must be a " + PKIXParameters.class.getName()
                    + " instance.");
        }

        ExtendedPKIXParameters paramsPKIX;
        if (params instanceof ExtendedPKIXParameters)
        {
            paramsPKIX = (ExtendedPKIXParameters)params;
        }
        else
        {
            paramsPKIX = ExtendedPKIXParameters.getInstance((PKIXParameters)params);
        }
        if (paramsPKIX.getTrustAnchors() == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "trustAnchors is null, this is not allowed for certification path validation.");
        }

        //
        // 6.1.1 - inputs
        //
        /**
         * (a) n 길이 의 인증경로 신뢰당사자는 번째 인증서를 검증하기 위해 생성한 인증경로 는 n ( { 1 , . . . , n } )
				다음을 만족해야 한다.
				․{1, ... , n-1} x x+1 . 중 인 증 서  의 소 유 자 는 인 증 서  의 발 급 자 이 어 야 한 다
				․인증서 1은 신뢰당사자가 신뢰하는 최상위인증기관정보를 이용해 발급된 인증서이다.
				․인증서 n은 신뢰당사자가 검증하길 원하는 대상인증서이다
         */
        
        List certs = certPath.getCertificates();
        int n = certs.size();

        if (certs.isEmpty())
        {
            throw new CertPathValidatorException("Certification path is empty.", null, certPath, 0);
        }

        //
        // (b)
        // 현재시각(T)
        // 대상인증서의 검증시각을 설정한다 초기값은 현재시각을 설정해야 한다 . .
        // Date validDate = CertPathValidatorUtilities.getValidDate(paramsPKIX);
        
        //
        // (c)사용자초기정책집합(user-initial-policy-set)
        //신뢰당사자가 수용가능한 인증서정책식별자를 설정한다 초기값은 상호연동 인증서 정책을 포함해야 한다
        Set userInitialPolicySet = paramsPKIX.getInitialPolicies();
        //
        // (d) 최상위인증기관정보
        // 인증서 경로검증 시 신뢰당사자가 이용하는 신뢰된 정보로써 다음과 같은
        // 정보를 포함하며, 초기값은 인증 경로구축 을 통해 구축된 최상위인증기관 정보를 설정해야 한다.
        // 
        // 최상위인증기관명칭
        // ․최상위인증기관공개키알고리즘
        // ․최상위인증기관공개키
        // ․최상위인증기관공개키파라미터(선택사항)
        
        TrustAnchor trust;
        try
        {
            trust = CertPathValidatorUtilities.findTrustAnchor((X509Certificate) certs.get(certs.size() - 1),
                    paramsPKIX.getTrustAnchors(), paramsPKIX.getSigProvider());
        }
        catch (AnnotatedException e)
        {
            throw new CertPathValidatorException(e.getMessage(), e, certPath, certs.size() - 1);
        }

        if (trust == null)
        {
            throw new CertPathValidatorException("Trust anchor for certification path not found.", null, certPath, -1);
        }

        //
        // (e), (f), (g) are part of the paramsPKIX object.
        //
        Iterator certIter;
        int index = 0;
        int i;
        // Certificate for each interation of the validation loop
        // Signature information for each iteration of the validation loop
        //
        // 6.1.2 - setup
        //

        //
        // (a)
        //
        List[] policyNodes = new ArrayList[n + 1];
        for (int j = 0; j < policyNodes.length; j++)
        {
            policyNodes[j] = new ArrayList();
        }

        Set policySet = new HashSet();

        policySet.add(RFC3280CertPathUtilities.ANY_POLICY);

        PKIXPolicyNode validPolicyTree = new PKIXPolicyNode(new ArrayList(), 0, policySet, null, new HashSet(),
                RFC3280CertPathUtilities.ANY_POLICY, false);

        policyNodes[0].add(validPolicyTree);

        //
        // (b) and (c)
        //
        PKIXNameConstraintValidator nameConstraintValidator = new PKIXNameConstraintValidator();

        // (d)
        //
        int explicitPolicy;
        Set acceptablePolicies = new HashSet();

        if (paramsPKIX.isExplicitPolicyRequired())
        {
            explicitPolicy = 0;
        }
        else
        {
            explicitPolicy = n + 1;
        }

        //
        // (e)
        //
        int inhibitAnyPolicy;

        if (paramsPKIX.isAnyPolicyInhibited())
        {
            inhibitAnyPolicy = 0;
        }
        else
        {
            inhibitAnyPolicy = n + 1;
        }

        //
        // (f)
        //
        int policyMapping;

        if (paramsPKIX.isPolicyMappingInhibited())
        {
            policyMapping = 0;
        }
        else
        {
            policyMapping = n + 1;
        }

        //
        // (g), (h), (i), (j)
        //
        PublicKey workingPublicKey;
        X500Principal workingIssuerName;

        X509Certificate sign = trust.getTrustedCert();
        try
        {
            if (sign != null)
            {
                workingIssuerName = CertPathValidatorUtilities.getSubjectPrincipal(sign);
                workingPublicKey = sign.getPublicKey();
            }
            else
            {
                workingIssuerName = new X500Principal(trust.getCAName());
                workingPublicKey = trust.getCAPublicKey();
            }
        }
        catch (IllegalArgumentException ex)
        {
            throw new CertPathValidatorException("Subject of trust anchor could not be (re)encoded.", ex, certPath,
                    -1);
        }

        AlgorithmIdentifier workingAlgId = null;
        try
        {
            workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
        }
        catch (CertPathValidatorException e)
        {
            throw new CertPathValidatorException(
                    "Algorithm identifier of public key of trust anchor could not be read.", e, certPath, -1);
        }
        DERObjectIdentifier workingPublicKeyAlgorithm = workingAlgId.getObjectId();
        DEREncodable workingPublicKeyParameters = workingAlgId.getParameters();

        //
        // (k)
        //
        int maxPathLength = n;

        //
        // 6.1.3
        //

        if (paramsPKIX.getTargetConstraints() != null
                && !paramsPKIX.getTargetConstraints().match((X509Certificate) certs.get(0)))
        {
            throw new CertPathValidatorException(
                    "Target certificate in certification path does not match targetConstraints.", null, certPath, 0);
        }

        // 
        // initialize CertPathChecker's
        //
        List pathCheckers = paramsPKIX.getCertPathCheckers();
        certIter = pathCheckers.iterator();
        while (certIter.hasNext())
        {
            ((PKIXCertPathChecker) certIter.next()).init(false);
        }

        X509Certificate cert = null;

        for (index = certs.size() - 1; index >= 0; index--)
        {

            // try
            // {
            //
            // i as defined in the algorithm description
            //
            i = n - index;

            //
            // set certificate to be checked in this round
            // sign and workingPublicKey and workingIssuerName are set
            // at the end of the for loop and initialized the
            // first time from the TrustAnchor
            //
            cert = (X509Certificate) certs.get(index);
            
            boolean verificationAlreadyPerformed = (index == certs.size() - 1);

            //
            // 6.1.3
            //

            RFC3280CertPathUtilities.processCertA(certPath, paramsPKIX, index, workingPublicKey,
                verificationAlreadyPerformed, workingIssuerName, sign);

            //인증서의 SubjectName과 SubjectAltName에 대한 nameConstraint 검사를 수행한다.
            RFC3280CertPathUtilities.processCertBC(certPath, index, nameConstraintValidator);
            //인증서 정책(policy)를 검사하고 유효한 policy를 얻어온다.
            validPolicyTree = RFC3280CertPathUtilities.processCertD(certPath, index, acceptablePolicies,
                    validPolicyTree, policyNodes, inhibitAnyPolicy);
            //인증서 정책(policy)을 얻어온다.
            validPolicyTree = RFC3280CertPathUtilities.processCertE(certPath, index, validPolicyTree);

            //인증서 정책이 명시(explicit)되어 있을경우 얻어진 유효한 인증서 정책이 있는지 검사한다.
            //명시 되어 있지 않은 경우 인증서 정책은 무시된다.
            RFC3280CertPathUtilities.processCertF(certPath, index, validPolicyTree, explicitPolicy);

            //
            // 6.1.4
            //

            if (i != n)
            {
            	//모든 인증서의 버전을 검사한다. 버전이 없거나 CA인증서일 경우에 1이면 오류이다.
                if (cert != null && cert.getVersion() == 1)
                {
                    throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", null,
                            certPath, index);
                }
                
                RFC3280CertPathUtilities.prepareNextCertA(certPath, index); //PolicyMapping을 검사한다. 없을경우 무시된다.

                validPolicyTree = RFC3280CertPathUtilities.prepareCertB(certPath, index, policyNodes, validPolicyTree,
                        policyMapping);

                RFC3280CertPathUtilities.prepareNextCertG(certPath, index, nameConstraintValidator);

                // (h)
                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertH1(certPath, index, explicitPolicy);
                policyMapping = RFC3280CertPathUtilities.prepareNextCertH2(certPath, index, policyMapping);
                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertH3(certPath, index, inhibitAnyPolicy);

                //
                // (i)
                //
                // 정책제한정보에 explicit에 관련된 제한이 있을경우 값을 설정함. 
                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertI1(certPath, index, explicitPolicy);
                // 정책제한정보에  policyMapping에 관련된 제한이 있을경우 값을 설정함.
                policyMapping = RFC3280CertPathUtilities.prepareNextCertI2(certPath, index, policyMapping);

                // (j)
                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertJ(certPath, index, inhibitAnyPolicy);

                // (k) 인증서가 Basic Constraint정보가 있을경우 CA인증서인지 확인함.
                RFC3280CertPathUtilities.prepareNextCertK(certPath, index);

                // (l) maxPathLength이 0일경우는 셀프 서명한 인증서(루트인증서)여야함.
                maxPathLength = RFC3280CertPathUtilities.prepareNextCertL(certPath, index, maxPathLength);

                // (m)maxPathLength값이 Basic Constraint의 값보다 크면 값을 Basic Constraint의 값으로 대체함. (대부분 0으로 바꿈)
                maxPathLength = RFC3280CertPathUtilities.prepareNextCertM(certPath, index, maxPathLength);

                // (n)키사용정책에 서명이 가능하도록 되어있는지 검사 (아니라면 에러)
                RFC3280CertPathUtilities.prepareNextCertN(certPath, index);

                Set criticalExtensions = cert.getCriticalExtensionOIDs();
                if (criticalExtensions != null)
                {
                    criticalExtensions = new HashSet(criticalExtensions);

                    // these extensions are handled by the algorithm
                    criticalExtensions.remove(RFC3280CertPathUtilities.KEY_USAGE);
                    criticalExtensions.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                    criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                    criticalExtensions.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                    criticalExtensions.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                    criticalExtensions.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                    criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                    criticalExtensions.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                    criticalExtensions.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                    criticalExtensions.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                }
                else
                {
                    criticalExtensions = new HashSet();
                }

                // (o) Recognize and process any other critical extension present in the certificate.
                //     Process any other recognized non-critical extension present in the certificate.
                RFC3280CertPathUtilities.prepareNextCertO(certPath, index, criticalExtensions, pathCheckers);
                
                // set signing certificate for next round
                sign = cert;

                // (c)
                workingIssuerName = CertPathValidatorUtilities.getSubjectPrincipal(sign);

                // (d)
                try
                {
                    workingPublicKey = CertPathValidatorUtilities.getNextWorkingKey(certPath.getCertificates(), index);
                }
                catch (CertPathValidatorException e)
                {
                    throw new CertPathValidatorException("Next working key could not be retrieved.", e, certPath, index);
                }

                workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                // (f)
                workingPublicKeyAlgorithm = workingAlgId.getObjectId();
                // (e)
                workingPublicKeyParameters = workingAlgId.getParameters();
            }
        }

        //
        // 6.1.5 Wrap-up procedure
        //

        explicitPolicy = RFC3280CertPathUtilities.wrapupCertA(explicitPolicy, cert);

        explicitPolicy = RFC3280CertPathUtilities.wrapupCertB(certPath, index + 1, explicitPolicy);

        //
        // (c) (d) and (e) are already done
        //

        //
        // (f)
        //
        Set criticalExtensions = cert.getCriticalExtensionOIDs();

        if (criticalExtensions != null)
        {
            criticalExtensions = new HashSet(criticalExtensions);
            // these extensions are handled by the algorithm
            criticalExtensions.remove(RFC3280CertPathUtilities.KEY_USAGE);
            criticalExtensions.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
            criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
            criticalExtensions.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
            criticalExtensions.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
            criticalExtensions.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
            criticalExtensions.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
            criticalExtensions.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
            criticalExtensions.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
            criticalExtensions.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
            criticalExtensions.remove(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS);
            
            criticalExtensions.remove(RFC3280CertPathUtilities.EXTENDED_KEY_USAGE);
            
        }
        else
        {
            criticalExtensions = new HashSet();
        }

        RFC3280CertPathUtilities.wrapupCertF(certPath, index + 1, pathCheckers, criticalExtensions);

        PKIXPolicyNode intersection = RFC3280CertPathUtilities.wrapupCertG(certPath, paramsPKIX, userInitialPolicySet,
                index + 1, policyNodes, validPolicyTree, acceptablePolicies);

        if ((explicitPolicy > 0) || (intersection != null))
        {
            return new PKIXCertPathValidatorResult(trust, intersection, cert.getPublicKey());
        }

        throw new CertPathValidatorException("Path processing failed on policy.", null, certPath, index);
    }

}
