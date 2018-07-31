package com.neo.security.certpath.store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.neo.security.asn1.ASN1Object;
import com.neo.security.asn1.DEROctetString;
import com.neo.security.asn1.x509.CRLDistPoint;
import com.neo.security.asn1.x509.DistributionPoint;
import com.neo.security.asn1.x509.DistributionPointName;
import com.neo.security.asn1.x509.GeneralName;
import com.neo.security.asn1.x509.GeneralNames;
import com.neo.security.asn1.x509.X509Extensions;
import com.neo.security.bcutil.Selector;
import com.neo.security.bcutil.StreamParsingException;
import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509HttpCertStoreParameters;
import com.neo.security.provider.X509CRLParser;
import com.neo.security.x509.X509CRLStoreSelector;
import com.neo.security.x509.X509StoreParameters;
import com.neo.security.x509.X509StoreSpi;

/**
 * A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
 * certificate revocation lists from an HTTP directory.
 *
 * @see com.kica.security.x509.sg.openews.x509.X509Store
 */
public class X509StoreHTTPCRLs extends X509StoreSpi
{
	private HTTPStoreHelper helper = null;
	
    public X509StoreHTTPCRLs()
    {
    	
    }

    /**
     * Initializes this HTTP CRL store implementation.
     *
     * @param params <code>X509HTTPCertStoreParameters</code>.
     * @throws IllegalArgumentException if <code>params</code> is not an instance of
     *                                  <code>X509HTTPCertStoreParameters</code>.
     */
    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509HttpCertStoreParameters))
        {
            throw new IllegalArgumentException(
                "Initialization parameters must be an instance of "
                    + X509HttpCertStoreParameters.class.getName() + ".");
        }
        
        helper = new HTTPStoreHelper((X509HttpCertStoreParameters)params);
        
    }

    /**
     * Returns a collection of matching CRLs from the HTTP location.
     * <p/>
     * The selector must be a of type <code>X509CRLStoreSelector</code>. If
     * it is not an empty collection is returned.
     * <p/>
     * The issuer should be a reasonable criteria for a selector.
     *
     * @param selector The selector to use for finding.
     * @return A collection with the matches.
     * @throws StoreException if an exception occurs while searching.
     */
    public Collection engineGetMatches(Selector selector) throws StoreException
    {
        if (!(selector instanceof X509CRLStoreSelector))
        {
            return Collections.EMPTY_SET;
        }
        X509CRLStoreSelector xselector = (X509CRLStoreSelector)selector;
        Set set = new HashSet();
        // test only delta CRLs should be selected
        if (xselector.isDeltaCRLIndicatorEnabled())
        {
        	set.addAll(getCertificateRevocationLists(xselector));
        }
        // nothing specified
        else
        {
        	set.addAll(getCertificateRevocationLists(xselector));
        }
        
        return set;
    }
    
    
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
    
	Collection getCertificateRevocationLists(X509CRLStoreSelector selector) throws StoreException
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
		
		ArrayList byteChunks = new ArrayList();
		
		for(int i=0; i < names.length ; i++)
		{
//			if (names[i].getTagNo() == GeneralName.uniformResourceIdentifier)
			if (names[i].getStringName().startsWith("http://") || names[i].getStringName().startsWith("https://"))
			{
				String url = names[i].getStringName();

				System.out.println("url: " + url);
				
				byteChunks.add(helper.downloadResource(url));
			}
		}

		return createCRLs(byteChunks, selector);	
	}
	

    
}
