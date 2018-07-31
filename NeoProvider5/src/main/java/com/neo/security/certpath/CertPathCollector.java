package com.neo.security.certpath;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import com.neo.security.asn1.x509.CRLDistPoint;
import com.neo.security.bcutil.Selector;
import com.neo.security.certpath.exception.NoSuchStoreException;
import com.neo.security.certpath.store.X509DirectoryStoreParameters;
import com.neo.security.certpath.store.X509StoreDirectory;
import com.neo.security.certpath.util.AmFile;
import com.neo.security.provider.NeoProvider;
import com.neo.security.provider.X509CertificateObject;
import com.neo.security.x509.X509CRLStoreSelector;
import com.neo.security.x509.X509CertStoreSelector;
import com.neo.security.x509.X509Store;

public class CertPathCollector
{
	public static final int CERTPATH = 0;
	public static final int CERT = 1;
	public static final int CRL = 2;

	//	private HashMap stores = new HashMap();

	private ArrayList certs = new ArrayList();
	private ArrayList crls = new ArrayList();

	private X509Store defaultStore = null;
	private X509Store cacheStore = null;

	private int defaultType = CERTPATH;

	private String certPath = null;

	public CertPathCollector()
	{
	}

	public CertPathCollector(CollectorParameter param)  throws NoSuchProviderException, NoSuchStoreException
	{
		if (param.getLdapAddress() != null)
		{
			String url = "ldap://" + param.getLdapAddress() + ":" + param.getLdapPort();
			X509LDAPCertStoreParameters params = new X509LDAPCertStoreParameters.Builder(url, "").build();

			defaultStore = X509Store.getInstance("LDAP", params, NeoProvider.PROVIDER_NAME);
		}

		if (param.getCachePath() != null)
		{
			certPath = param.getCachePath();
			cacheStore = X509Store.getInstance("CACHE", new X509DirectoryStoreParameters(certPath), NeoProvider.PROVIDER_NAME);
		}
	}

	public Collection downloadCert(String url, String dn)  throws CertPathBuilderException
	{
		X509Store store = CRLDistPointUtillities.getAdditionalStoreFromLocation(url);
		
		X509CertStoreSelector certSelect = new X509CertStoreSelector();
		try
		{
			certSelect.setSubject(new X500Principal(dn).getEncoded());
		}
		catch (IOException ex)
		{
			throw new CertPathBuilderException(
					"Subject criteria for certificate selector to find issuer certificate could not be set.", ex);
		}

		return getStoreMatches(store,certSelect);
		//�씤利앹꽌瑜� �떎�슫濡쒕뱶�븯�뿬 ���옣�븳�떎.
//		List matchedCerts = new ArrayList(getStoreMatches(store,certSelect));
//		if (matchedCerts.size() > 0)
//		{
//			return (X509Certificate) matchedCerts.get(0);
//		}
//
//		throw new CertPathBuilderException("Issuer certificate cannot be searched.");
	}

	
	public X509Certificate downloadIssuerCert(X509Certificate cert)  throws CertPathBuilderException
	{
		cert = getX509CertObject(cert);

		X509CertStoreSelector certSelect = new X509CertStoreSelector();
		try
		{
			certSelect.setSubject(cert.getIssuerX500Principal().getEncoded());
		}
		catch (IOException ex)
		{
			throw new CertPathBuilderException(
					"Subject criteria for certificate selector to find issuer certificate could not be set.", ex);
		}

		X509Store store = defaultStore == null ? (new CRLDistPointUtillities(cert)).getLDAPStore() : defaultStore;

		List matchedCerts = new ArrayList(getStoreMatches(store,certSelect));
		if (matchedCerts.size() > 0)
		{
			return (X509Certificate) matchedCerts.get(0);
		}

		throw new CertPathBuilderException("Issuer certificate cannot be searched.");
	}

	public List downloadCertPath(List certs)  throws CertPathBuilderException
	{
		this.certs.clear();
		crls.clear();
		
//		this.defaultType = CRL; //CRL留� �떎�슫濡쒕뱶 媛��뒫�븯�룄濡� �젙�쓽�븳�떎.
		
		this.certs.addAll(certs);

		try {
			Iterator it = certs.iterator();
			while(it.hasNext())
				appendCertsAndCrls(getX509CertObject((X509Certificate)it.next()));
		} catch (AnnotatedException e) {
			throw new CertPathBuilderException(e);
		}

		return crls;
	}


	public List downloadCertPath(int type, X509Certificate cert)  throws CertPathBuilderException
	{
		certs.clear();
		crls.clear();

		this.defaultType = type;

		cert = getX509CertObject(cert);

		certs.add(cert);

		try {
			appendCertsAndCrls(cert);
		} catch (AnnotatedException e) {
			throw new CertPathBuilderException(e);
		}

		ArrayList result = new ArrayList(certs);
		result.addAll(crls);



		//		for(int i=0; i < certs.size() ;i++)
		//		{
		//			System.out.println(((X509Certificate)certs.get(i)).getSubjectDN().getName());
		//		}
		//		
		//		for(int i=0; i < crls.size() ;i++)
		//		{
		//			System.out.println(((X509CRL)crls.get(i)).getIssuerDN().getName());
		//		}
		//		
		return result;
	}

	public List getCertificateChain() 
	{
		return certs;
	}

	public List getCRLs() 
	{
		return crls;
	}

	X509Certificate getX509CertObject(X509Certificate cert) throws CertPathBuilderException
	{
		if (!(cert instanceof X509CertificateObject))
		{
			try {
				return (X509Certificate)CertificateFactory.getInstance("X.509",NeoProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
			} catch (CertificateException e) {
				throw new CertPathBuilderException(e);
			} catch (NoSuchProviderException e) {
				throw new CertPathBuilderException(e);
			}
		}

		return cert;
	}

	Collection getStoreMatches( X509Store store,Selector selector)
	{
		ArrayList matched = new ArrayList();

		if (cacheStore != null)
		{
			matched.addAll(cacheStore.getMatches(selector));
		}

		if (matched.size() == 0)
		{
			try 
			{
				matched.addAll(store.getMatches(selector));
			} catch(Exception ex)
			{

			}
			//			System.out.println("matched.size()=" + matched.size());
			if (cacheStore != null && matched.size() > 0)
			{
				try 
				{
					if (selector instanceof X509CertStoreSelector)
					{
						saveFile(X509StoreDirectory.getCertificateName((X509CertStoreSelector)selector),
								((X509Certificate)matched.get(0)).getEncoded());
					}
					else if (selector instanceof X509CRLStoreSelector)
					{
						String name = X509StoreDirectory.getCRLName((X509CRLStoreSelector)selector);
						for(int i=0; i < matched.size();i++)
							saveFile(name + "(" + i  + ").crl",((X509CRL)matched.get(i)).getEncoded());
					}
				}
				catch(CertificateEncodingException ex)
				{
					ex.printStackTrace();
				}
				catch(StoreException ex)
				{
					ex.printStackTrace();
				}
				catch(CRLException ex)
				{
					ex.printStackTrace();
				}
			}
		}

		return matched;
	}

	void saveFile(String filename, byte[] encoded)
	{
		//		System.out.println("SaveFile: (" + encoded.length + ") " + filename);
		FileOutputStream out = null;
		try {
//			out = new FileOutputStream(certPath + File.separator + filename);
			out = new AmFile(certPath + File.separator + filename).getFileOutputStream();


			out.write(encoded);
		}catch(IOException ex)
		{
			System.err.println("Failed to save a cache file: " + ex.getMessage());
		}
		finally{
			if (out != null) try{out.close();}catch(IOException e){}
		}
	}

	void appendCertsAndCrls(X509Certificate cert) throws AnnotatedException
	{
		// 諛쒓툒�옄 �씤利앹꽌瑜� 李얠쓣�닔 �뾾�쓣 寃쎌슦�뿉�뒗 �씤利앹꽌 CRL_DP�뿉�꽌 異붽� Store瑜� �깮�꽦�븯�뿬 異붽��븯怨� �떎�떆 寃��깋�븳�떎.
		CRLDistPoint crldp = null;
		try
		{
			crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(cert,
					RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS));
		}
		catch (Exception e)
		{
			throw new AnnotatedException("CRL distribution point extension could not be read.", e);
		}

		
		
		
		Collection stores  = new HashSet(); 
		
		if (defaultStore == null && crldp == null)
		{
			return;
		}
		else if (defaultStore == null)
		{
			stores.addAll((new CRLDistPointUtillities(crldp)).getAdditionalStores());
		}
		else
		{
			stores.add(defaultStore);
		}
		
		//X509Store store = defaultStore == null ? (new CRLDistPointUtillities(crldp)).getAdditionalStores() : defaultStore;

		if (defaultType == CERTPATH || defaultType == CRL)
		{
			//CRL�쓣 �떎�슫濡쒕뱶�븯�뿬 ���옣�븳�떎.
			X509CRLStoreSelector crlSelector = new X509CRLStoreSelector();
			crlSelector.setIssuingDistributionPoint(crldp.getDEREncoded());

			Iterator it = stores.iterator();
			while(it.hasNext())
				crls.addAll(getStoreMatches((X509Store)it.next(),crlSelector));
			
			if (defaultType == CRL) //CRL留� �떎�슫濡쒕뱶 諛쏆쓣�븣�뒗 �긽�쐞 �씤利앹꽌瑜� �뼸吏� �븡�뒗�떎.
				return;
		}

		//�씤利앹꽌瑜� �떎�슫濡쒕뱶�븯�뿬 ���옣�븳�떎.
		X509CertStoreSelector certSelect = new X509CertStoreSelector();
		try
		{
			certSelect.setSubject(cert.getIssuerX500Principal().getEncoded());
		}
		catch (IOException ex)
		{
			throw new AnnotatedException(
					"Subject criteria for certificate selector to find issuer certificate could not be set.", ex);
		}
		List matchedCerts = new ArrayList();
		
		Iterator it = stores.iterator();
		while(it.hasNext())
			matchedCerts.addAll(getStoreMatches((X509Store)it.next(),certSelect));
		
		if (matchedCerts.size() > 0)
		{
			X509Certificate issuer = (X509Certificate) matchedCerts.get(0);

			//CRL留� �떎�슫濡쒕뱶 �븯�뒗寃쎌슦媛� �븘�땲硫� �씤利앹꽌瑜� 異붽��븳�떎.
			if (defaultType != CRL)
				certs.add(issuer);

			//ROOT CA�씤利앹꽌媛� �븘�땲硫� �옱洹��샇異쒕줈 �떎�떆 �떆�옉�븳�떎.
			if (issuer.getSubjectDN().equals(issuer.getIssuerDN()) == false)
			{
				appendCertsAndCrls(issuer);
			}
		}

	}
}
