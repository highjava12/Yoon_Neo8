package com.neo.security.certpath.store;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;

import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509LDAPCertStoreParameters;

class LDAPHelper {

	public synchronized static LDAPHelper getInstance(X509LDAPCertStoreParameters params)
	{
		return new LDAPHelper(params);
	}
	
	private LDAPHelperSPI spi = null;
	
	protected LDAPHelper(X509LDAPCertStoreParameters params)
	{
		boolean supportJNDI = true;
		try {

			 AccessController.doPrivileged(new PrivilegedAction()
		        {
		            public Object run()
		            {
		            	
		            	try {
							return Class.forName("javax.naming.directory.InitialDirContext").newInstance();
						} catch (InstantiationException e) {
							throw new IllegalStateException("not supported");
						} catch (IllegalAccessException e) {
							throw new IllegalStateException("not supported");
						} catch (ClassNotFoundException e) {
							throw new IllegalStateException("not supported");
						}
		            }
		        });
		}
		catch(Exception ex)
		{
			supportJNDI = false;	
		}

		if (supportJNDI)
			spi = new LDAPJndiHelper(params);
		else 
			spi = new LDAPNetscapeHelper(params);
	}
	
	public List getLdapAttributeValues(String dn, String[] requestedAttributes) throws StoreException
	{
		return spi.engineGetLdapAttributeValues(dn, requestedAttributes);
	}
	
	public static interface LDAPHelperSPI {
		public List engineGetLdapAttributeValues(String dn, String[] requestedAttributes) throws StoreException;
	}
}
