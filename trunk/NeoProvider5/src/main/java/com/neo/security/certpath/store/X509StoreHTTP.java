package com.neo.security.certpath.store;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.neo.security.bcutil.Selector;
import com.neo.security.bcutil.StreamParsingException;
import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509HttpCertStoreParameters;
import com.neo.security.provider.X509CertParser;
import com.neo.security.x509.X509CRLStoreSelector;
import com.neo.security.x509.X509CertStoreSelector;
import com.neo.security.x509.X509StoreParameters;
import com.neo.security.x509.X509StoreSpi;

/**
 * A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
 * certificates form a HTTP server.
 *
 * @see com.kica.security.x509.sg.openews.x509.X509Store
 */
public class X509StoreHTTP
    extends X509StoreSpi
{

    private HTTPStoreHelper helper;

    public X509StoreHTTP()
    {
    } 

    /**
     * Initializes this HTTP cert store implementation.
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
     * Returns a collection of matching certificates from the HTTP location.
     * <p/>
     * The selector must be a of type <code>X509CertStoreSelector</code>. If
     * it is not an empty collection is returned.
     * <p/>
     * The implementation searches only for CA certificates, if the method
     * {@link java.security.cert.X509CertSelector#getBasicConstraints()} is
     * greater or equal to 0. If it is -2 only end certificates are searched.
     * <p/>
     * The subject and the serial number for end certificates should be
     * reasonable criterias for a selector.
     *
     * @param selector The selector to use for finding.
     * @return A collection with the matches.
     * @throws StoreException if an exception occurs while searching.
     */
    public Collection engineGetMatches(Selector selector) throws StoreException
    {
        if (selector instanceof X509CertStoreSelector)
        {
            return getCertMatches(selector);
        }
        else if (selector instanceof X509CRLStoreSelector)
        {
        	return getCRLMatches(selector);
        }
        else
        	return Collections.EMPTY_SET;
        
    }
    
    private Collection getCRLMatches(Selector selector) throws StoreException
    {
    	return null;
    }
    
    private Collection getCertMatches(Selector selector) throws StoreException
    {
    	
        X509CertStoreSelector xselector = (X509CertStoreSelector)selector;

        byte[] certData = helper.downloadResource();
        
        Set set = new HashSet();
        
        X509CertParser parser = new X509CertParser();
		parser.engineInit(new ByteArrayInputStream( certData ));

		try {
			
			X509Certificate cert = (X509Certificate)parser.engineRead();
			
			if (selector.match(cert))
				set.add(cert);
		} catch (StreamParsingException e) {
			throw new StoreException("Certificate Parsing Error: ",e);
		}
		
        return set;
    }

}
