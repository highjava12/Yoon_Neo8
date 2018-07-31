package com.neo.security.certpath;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import com.neo.security.asn1.DERIA5String;
import com.neo.security.asn1.x509.CRLDistPoint;
import com.neo.security.asn1.x509.DistributionPoint;
import com.neo.security.asn1.x509.DistributionPointName;
import com.neo.security.asn1.x509.GeneralName;
import com.neo.security.asn1.x509.GeneralNames;
import com.neo.security.provider.NeoProvider;
import com.neo.security.provider.X509CertificateObject;
import com.neo.security.x509.X509CertStoreSelector;
import com.neo.security.x509.X509Store;

public class CRLDistPointUtillities
{
	private CRLDistPoint crldp;
	private String[] locations = null;
	
	
	public CRLDistPointUtillities(X509Certificate x509Cert) throws CertPathBuilderException
	{
		X509Certificate cert = x509Cert;
		if (!(x509Cert instanceof X509CertificateObject))
		{
			try {
				cert = (X509Certificate)CertificateFactory.getInstance("X.509",NeoProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream(x509Cert.getEncoded()));
			} catch (CertificateException e) {
				throw new CertPathBuilderException(e);
			} catch (NoSuchProviderException e) {
				throw new CertPathBuilderException(e);
			}
		}

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

		try
		{
			crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(cert,
					RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS));
			
			locations = this.getCRLDistributionPointLocation(crldp);
		}
		catch (Exception e)
		{
			throw new CertPathBuilderException("CRL distribution point extension could not be read.", e);
		}
	}

	public CRLDistPointUtillities(CRLDistPoint crldp)
	{
		this.crldp = crldp;
		
		locations = this.getCRLDistributionPointLocation(crldp);
	}


	public Collection getAdditionalStores()
	{
		HashSet stores = new HashSet();
		for(int i=0; i < locations.length;i++)
		{
			stores.add(getAdditionalStoreFromLocation(locations[i]));
		}

		return stores;
	}
	
	public X509Store getLDAPStore()
	{
		String ldapLocation = getLdapLocation();
		
		return getAdditionalStoreFromLocation(ldapLocation);
	}

//	public String getCRLFileName()
//	{
//		return getFileNameFromLocation(getCRLDistributionPointLocation(crldp));
//	}

	public String getLdapLocation()
	{
		for (int i=0; i < locations.length ; i++)
		{
			if (locations[i].startsWith("ldap://"))
				return locations[i];
		}
		
		return null;
	}
	
	public String[] getLdapLocations()
	{
		return getCRLDistributionPointLocation(crldp);
	}
	
	String[] getCRLDistributionPointLocation(CRLDistPoint crldp)
	{
		if (crldp != null)
		{
			DistributionPoint dps[] = null;
			try
			{
				dps = crldp.getDistributionPoints();
			}
			catch (Exception e)
			{
				throw new RuntimeException("Distribution points could not be read.",e);
			}
			
			ArrayList locations = new ArrayList();
			for (int i = 0; i < dps.length; i++)
			{
				DistributionPointName dpn = dps[i].getDistributionPoint();
				// look for URIs in fullName
				if (dpn != null)
				{
					if (dpn.getType() == DistributionPointName.FULL_NAME)
					{
						GeneralName[] genNames = GeneralNames.getInstance(
								dpn.getName()).getNames();
						// look for an URI
						for (int j = 0; j < genNames.length; j++)
						{
							if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
							{
								String location = DERIA5String.getInstance(
										genNames[j].getName()).getString();

//								if (location.startsWith("ldap://"))
//									return location;
								
								locations.add(location);
							}
						}
					}
				}
			}
			
			return (String[])locations.toArray(new String[0]);
		}

		return null;
	}

	static String getFileNameFromLocation(String location)
	{
		try
		{
			if (location.startsWith("ldap://"))
			{
				// ldap://directory.d-trust.net/CN=D-TRUST
				// Qualified CA 2003 1:PN,O=D-Trust GmbH,C=DE
				// skip "ldap://"
				location = location.substring(7);
				// after first / baseDN starts
				String base = null;
				if (location.indexOf("/") != -1)
				{
					base = location.substring(location.indexOf("/") + 1);

					return URLDecoder.decode((base.indexOf("?") != -1) ? base.substring(0,base.indexOf("?")) : base);
				}
			}

			return null;
		}
		catch (Exception e)
		{
			throw new StoreException("Exception adding X.509 stores.");
		}
	}

	public static X509Store getAdditionalStoreFromLocation(String location)
	{
		try
		{
			if (location == null)
			{
				return null;
			}
			else if (location.startsWith("ldap://"))
			{
				// ldap://directory.d-trust.net/CN=D-TRUST
				// Qualified CA 2003 1:PN,O=D-Trust GmbH,C=DE
				// skip "ldap://"
				location = location.substring(7);
				// after first / baseDN starts
				String base = null;
				String url = null;
				if (location.indexOf("/") != -1)
				{
					base = location.substring(location.indexOf("/"));
					// URL
					url = "ldap://"
							+ location.substring(0, location.indexOf("/"));
				}
				else
				{
					url = "ldap://" + location;
				}

				X509LDAPCertStoreParameters params = new X509LDAPCertStoreParameters.Builder(
						url, base).build();

				return X509Store.getInstance("LDAP", params, NeoProvider.PROVIDER_NAME);
			}
			else if (location.startsWith("http://") || location.startsWith("https://"))
			{
				X509HttpCertStoreParameters params = new X509HttpCertStoreParameters.Builder().build();
				
				return X509Store.getInstance("HTTP",params,NeoProvider.PROVIDER_NAME);
			}
				

			return null;
		}
		catch (Exception e)
		{
			// cannot happen
			e.printStackTrace();
			throw new RuntimeException("Exception adding X.509 stores.");
		}
	}
}
