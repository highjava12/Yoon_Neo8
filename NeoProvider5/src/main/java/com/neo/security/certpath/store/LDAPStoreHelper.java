package com.neo.security.certpath.store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import com.neo.security.asn1.ASN1Object;
import com.neo.security.asn1.DEROctetString;
import com.neo.security.asn1.x509.CRLDistPoint;
import com.neo.security.asn1.x509.DistributionPoint;
import com.neo.security.asn1.x509.DistributionPointName;
import com.neo.security.asn1.x509.GeneralName;
import com.neo.security.asn1.x509.GeneralNames;
import com.neo.security.asn1.x509.X509Extensions;
import com.neo.security.asn1.x509.X509Name;
import com.neo.security.bcutil.StreamParsingException;
import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509LDAPCertStoreParameters;
import com.neo.security.provider.X509CRLParser;
import com.neo.security.provider.X509CertParser;
import com.neo.security.x509.X509CRLStoreSelector;
import com.neo.security.x509.X509CertStoreSelector;

/**
 * This is a general purpose implementation to get X.509 certificates, CRLs,
 * attribute certificates and cross certificates from a LDAP location.
 * <p/>
 * At first a search is performed in the ldap*AttributeNames of the
 * {@link com.neo.security.certpath.X509LDAPCertStoreParameters} with the given
 * information of the subject (for all kind of certificates) or issuer (for
 * CRLs), respectively, if a {@link com.kica.security.x509.sg.openews.x509.X509CertStoreSelector} or
 * {@link com.sg.openews.x509.X509AttributeCertificate} is given with that
 * details.
 * <p/>
 * For the used schemes see:
 * <ul>
 * <li><a href="http://www.ietf.org/rfc/rfc2587.txt">RFC 2587</a>
 * <li><a
 * href="http://www3.ietf.org/proceedings/01mar/I-D/pkix-ldap-schema-01.txt">Internet
 * X.509 Public Key Infrastructure Additional LDAP Schema for PKIs and PMIs</a>
 * </ul>
 */
class LDAPStoreHelper
{

	// TODO: cache results

	private X509LDAPCertStoreParameters params;
	private LDAPHelper ldap = null;

	public LDAPStoreHelper(X509LDAPCertStoreParameters params)
	{
		this.params = params;

		ldap = LDAPHelper.getInstance(params);
	}

	private Set createCerts(List list, X509CertStoreSelector xselector)
			throws StoreException
	{
		Set certSet = new HashSet();


		Iterator it = list.iterator();

        X509CertParser parser = new X509CertParser();
        while (it.hasNext())
        {
            try
            {
                parser.engineInit(new ByteArrayInputStream((byte[])it
                    .next()));
                X509Certificate cert = (X509Certificate)parser
                    .engineRead();
                if (xselector.match((Object)cert))
                {
                    certSet.add(cert);
                }

            }
            catch (Exception e)
            {

            }
        }
		

		return certSet;
	}


	public static final String[] USER_CERT = {"userCertificate","userCertificate;binary"};
	public static final String[] CA_CERT = {"cACertificate","cACertificate;binary"};
	public static final String[] CERT_ALL = {"cACertificate","cACertificate;binary","userCertificate","userCertificate;binary"};
	
	public static final String[] CROSS_CERT = {"crossCertificatePair","crossCertificatePair;binary"};
	public static final String[] CRL = {"certificateRevocationList","certificateRevocationList;binary"};
	public static final String[] ARL = {"authorityRevocationList","authorityRevocationList;binary"};
	public static final String[] DELTA_CRL = {"deltaRevocationList","deltaRevocationList;binary"};

	public static final String[] CRL_ALL = {"deltaRevocationList","deltaRevocationList;binary","certificateRevocationList","certificateRevocationList;binary","authorityRevocationList","authorityRevocationList;binary"};

	private Set createCRLs(List list, X509CRLStoreSelector xselector)
			throws StoreException
			{
		Set crlSet = new HashSet();

        X509CRLParser parser = new X509CRLParser();
        Iterator it = list.iterator();
        while (it.hasNext())
        {
            try
            {
                parser.engineInit(new ByteArrayInputStream((byte[])it
                    .next()));
                X509CRL crl = (X509CRL)parser.engineRead();
                if (xselector.match((Object)crl))
                {
                    crlSet.add(crl);
                }
            }
            catch (StreamParsingException e)
            {

            }
        }

		return crlSet;
	}

	Collection getCertificateRevocationLists(X509CRLStoreSelector selector, String[] requestedAttributes ) throws StoreException
	{
		byte[] crldpData = selector.getIssuingDistributionPoint();
		if (crldpData == null)
		{
			if (selector.getCertificateChecking() != null)
			{
				byte[] extValue = selector.getCertificateChecking().getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
				try {
					crldpData = DEROctetString.getInstance(ASN1Object.fromByteArray(extValue)).getOctets();
				} catch (IOException e) {
					throw new StoreException("Illegal certificate extension(" + X509Extensions.CRLDistributionPoints.getId() +") value.",e);
				}
			}	
			else
				throw new StoreException("Illegal X509CRLStoreSelector, cannot get IssuingDistributionPoint or CertificateChecking!");
		}

		CRLDistPoint crldp;
		try {
			crldp = CRLDistPoint.getInstance(ASN1Object.fromByteArray(crldpData));
		} catch (IOException e) {
			throw new StoreException("Illegal IssuingDistributionPoint Value.",e);
		}
		
		DistributionPoint dp = crldp.getDistributionPoints()[0];

		DistributionPointName dpn = dp.getDistributionPoint();

		GeneralNames dps = GeneralNames.getInstance(dpn.getName());
		GeneralName[] names = dps.getNames();
		X509Name name = null;
		for(int i=0; i < names.length ; i++)
		{
			if (names[i].getTagNo() == 4)
			{
				name = X509Name.getInstance(names[i].getName());
				break;
			} 
			else if (names[i].getStringName().startsWith("ldap://"))
			{
				String url = names[i].getStringName();

//				System.out.println("url: " + url);
//				System.out.println("crldp: " + URLDecoder.decode(url.substring(url.indexOf('/', "ldap://".length()) + 1)));
				
//				int start = url.indexOf('/', "ldap://".length()) + 1;
				int start = url.lastIndexOf('/') + 1;
				int end =  url.indexOf('?') == -1 ? url.length() : url.indexOf('?');
				
				name = new X509Name(true,URLDecoder.decode(url.substring(start,end)));
			}
		}

		if (name == null)
			throw new StoreException("Illegal CRLSelector, cannot find distributionPoint name!");

		String searchDN = name.toString(true);
		
		List list = (List)getFromCache(searchDN + "?" + requestedAttributes[0]);
		
		if (list == null)
		{
			list = ldap.getLdapAttributeValues(name.toString(true),requestedAttributes);
		
			if (list.size() > 0)
				addToCache(searchDN + "?" + requestedAttributes[0],list);
		}
		
		return createCRLs(list, selector);	
	}

	public Collection getCertificates(X509CertStoreSelector selector) throws StoreException
	{

		String subject = this.getSubjectAsString(selector);

		List list = ldap.getLdapAttributeValues(subject,CERT_ALL);

		return createCerts(list, selector);
	}

	/**
	 * Returns end certificates.
	 * <p/>
	 * The attributeDescriptorCertificate is self signed by a source of
	 * authority and holds a description of the privilege and its delegation
	 * rules.
	 *
	 * @param selector The selector to find the certificates.
	 * @return A possible empty collection with certificates.
	 * @throws StoreException
	 */
	public Collection getUserCertificates(X509CertStoreSelector selector) throws StoreException
	{

		String subject = this.getSubjectAsString(selector);

		List list = ldap.getLdapAttributeValues(subject,USER_CERT);

		return createCerts(list, selector);
	}

	/**
	 * Returns CA certificates.
	 * <p/>
	 * The cACertificate attribute of a CA's directory entry shall be used to
	 * store self-issued certificates (if any) and certificates issued to this
	 * CA by CAs in the same realm as this CA.
	 *
	 * @param selector The selector to find the certificates.
	 * @return A possible empty collection with certificates.
	 * @throws StoreException
	 */
	public Collection getCACertificates(X509CertStoreSelector selector)
			throws StoreException
	{


		String subject = this.getSubjectAsString(selector);

		List list = ldap.getLdapAttributeValues(subject,CA_CERT);

		return createCerts(list, selector);

	}
	
	/**
	 * Returns the CRLs for issued certificates for other CAs matching the given
	 * selector. <br>
	 * The authorityRevocationList attribute includes revocation information
	 * regarding certificates issued to other CAs.
	 *
	 * @param selector The CRL selector to use to find the CRLs.
	 * @return A possible empty collection with CRLs
	 * @throws StoreException
	 */
	public Collection getAuthorityRevocationLists(X509CRLStoreSelector selector) throws StoreException
	{
		return getCertificateRevocationLists(selector,ARL);
	}

	/**
	 * Returns the delta revocation list for revoked certificates.
	 *
	 * @param selector The CRL selector to use to find the CRLs.
	 * @return A possible empty collection with CRLs.
	 * @throws StoreException
	 */
	public Collection getDeltaCertificateRevocationLists(X509CRLStoreSelector selector) throws StoreException
	{
		return getCertificateRevocationLists(selector,DELTA_CRL);
	}

	/**
	 * Returns the certificate revocation lists for revoked certificates.
	 *
	 * @param selector The CRL selector to use to find the CRLs.
	 * @return A possible empty collection with CRLs.
	 * @throws StoreException
	 */
	public Collection getCertificateRevocationLists(X509CRLStoreSelector selector) throws StoreException
	{
		return getCertificateRevocationLists(selector,CRL);
	}

	public Collection getAllCertificateRevocationLists(X509CRLStoreSelector selector) throws StoreException
	{
		return getCertificateRevocationLists(selector,CRL_ALL);
	}
	
	private Map cacheMap = new HashMap(cacheSize);

	private static int cacheSize = 32;

	private static long lifeTime = 60 * 1000;

	private synchronized void addToCache(String searchCriteria, List list)
	{
		Date now = new Date(System.currentTimeMillis());
		List cacheEntry = new ArrayList();
		cacheEntry.add(now);
		cacheEntry.add(list);
		if (cacheMap.containsKey(searchCriteria))
		{
			cacheMap.put(searchCriteria, cacheEntry);
		}
		else
		{
			if (cacheMap.size() >= cacheSize)
			{
				// replace oldest
				Iterator it = cacheMap.entrySet().iterator();
				long oldest = now.getTime();
				Object replace = null;
				while (it.hasNext())
				{
					Map.Entry entry = (Map.Entry)it.next();
					long current = ((Date)((List)entry.getValue()).get(0))
							.getTime();
					if (current < oldest)
					{
						oldest = current;
						replace = entry.getKey();
					}
				}
				cacheMap.remove(replace);
			}
			cacheMap.put(searchCriteria, cacheEntry);
		}
	}

	private List getFromCache(String searchCriteria)
	{
		List entry = (List)cacheMap.get(searchCriteria);
		long now = System.currentTimeMillis();
		if (entry != null)
		{
			// too old
			if (((Date)entry.get(0)).getTime() < (now - lifeTime))
			{
				return null;
			}
			return (List)entry.get(1);
		}
		return null;
	}

	/*
	 * spilt string based on spaces
	 */
	private String[] splitString(String str)
	{
		return str.split("\\s+");
	}

	private String getSubjectAsString(X509CertStoreSelector xselector)
	{
		try
		{
			byte[] encSubject = xselector.getSubjectAsBytes();
			if (encSubject != null)
			{
				return new X500Principal(encSubject).getName("RFC1779");
			}
		}
		catch (IOException e)
		{
			throw new StoreException("exception processing name: " + e.getMessage(), e);
		}
		return null;
	}

	private X500Principal getCertificateIssuer(X509Certificate cert)
	{
		return cert.getIssuerX500Principal();
	}
}
