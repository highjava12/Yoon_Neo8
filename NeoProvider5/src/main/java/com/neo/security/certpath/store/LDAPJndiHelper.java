package com.neo.security.certpath.store;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509LDAPCertStoreParameters;

class LDAPJndiHelper implements LDAPHelper.LDAPHelperSPI{

	
	/**
	 * Processing referrals..
	 */
	private static String REFERRALS_IGNORE = "ignore";

	/**
	 * Security level to be used for LDAP connections.
	 */
	private static final String SEARCH_SECURITY_LEVEL = "none";


	/**
	 * Initial Context Factory.
	 */
	private static final String[] LDAP_PROVIDERS = {"com.sun.jndi.ldap.LdapCtxFactory", "com.ibm.jndi.LDAPCtxFactory"};
	/**
	 * Package Prefix for loading URL context factories.
	 */
	private static final String[] URL_CONTEXT_PREFIXS = {"com.sun.jndi.url", "com.ibm.jndi"};

	private static int PROVIDER_NUMBER = 0;

	private final static Attributes EMPTY_ATTRIBUTES = new BasicAttributes();
	

	private final static byte[][] BB0 = new byte[0][];

	
	static {
		for (int i=0; i < LDAP_PROVIDERS.length ; i++)
		{
			try {
				Class cls = Class.forName(LDAP_PROVIDERS[i]);
				PROVIDER_NUMBER = i;
				break;
			}catch(Exception ex)
			{
				continue;
			}
		}
	}
	

	Properties props = new Properties();
	
	private X509LDAPCertStoreParameters params = null;
	
	public LDAPJndiHelper(X509LDAPCertStoreParameters params)
	{
		this.params = params;
	}
	
	
	public List engineGetLdapAttributeValues(String dn, String[] requestedAttributes) throws StoreException
	{
		DirContext ctx = null;
		try {
			ctx = connectLDAP();

//			if (requestedAttributes[0].equals("cACertificate") || requestedAttributes[1].equals("cACertificate"))
//				(new Exception("")).printStackTrace();
				
			ArrayList valueList = new ArrayList();

			Attributes attrs;
			try {
				attrs = ctx.getAttributes(dn, requestedAttributes);
			} catch (NameNotFoundException e) {
				// name does not exist on this LDAP server
				// treat same as not attributes found
				attrs = EMPTY_ATTRIBUTES;
			}

			for (int i=0; i < requestedAttributes.length ; i++) {
				String attrId = requestedAttributes[i];
				Attribute attr = attrs.get(attrId);
				byte[][] values = getAttributeValues(attr);
				for(int v = 0; v < values.length ; v++)
					valueList.add(values[v]);
			}

//			System.out.println("downloaded dn: " + valueList.size() + " >> " + (dn.length() > 50 ? dn.substring(0, 50) + "..." : dn) + "?" + requestedAttributes[0]);

			return valueList;
		}
		catch (NamingException e)
		{
			// skip exception, unfortunately if an attribute type is not
			// supported an exception is thrown

//						e.printStackTrace();

//			e.printStackTrace();
			
			throw new StoreException(e.getMessage());
			
//			return new ArrayList();
//			throw new StoreException("LDAP Error. ",e);
		}
		finally
		{
			try
			{
				if (null != ctx)
				{
					ctx.close();
				}
			}
			catch (Exception e)
			{
			}
		}
	}


	

	private DirContext connectLDAP() throws NamingException
	{
//		System.out.println("connect to " +  params.getLdapURL());
		
		
		props.setProperty(Context.INITIAL_CONTEXT_FACTORY, LDAP_PROVIDERS[PROVIDER_NUMBER]);
		props.setProperty(Context.URL_PKG_PREFIXES, URL_CONTEXT_PREFIXS[PROVIDER_NUMBER]);
		props.setProperty(Context.BATCHSIZE, "0");
		props.setProperty(Context.PROVIDER_URL, params.getLdapURL());
		props.setProperty(Context.REFERRAL, REFERRALS_IGNORE);
		props.setProperty(Context.SECURITY_AUTHENTICATION,
				SEARCH_SECURITY_LEVEL);

		return (DirContext) AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
            	try {
            		return new InitialDirContext(props);
            	}catch(NamingException e)
            	{
            		 throw new IllegalStateException(e.getMessage());
            	}
            }
        });
		
//		DirContext ctx = new InitialDirContext(props);
//		return ctx;
	}
	
	private byte[][] getAttributeValues(Attribute attr) 
			throws NamingException {
		byte[][] values;
		if (attr == null) {
			values = BB0;
		} else {
			NamingEnumeration en = attr.getAll();
			//System.out.println("attribute size: " + attr.size());
			values = new byte[attr.size()][];
			for(int i=0; i < attr.size() ; i++)
			{
				values[i] = (byte[])attr.get(i);
				//System.out.println("downloaded length: " + values[i].length);

			}
		}
	
		return values;
	}

}
