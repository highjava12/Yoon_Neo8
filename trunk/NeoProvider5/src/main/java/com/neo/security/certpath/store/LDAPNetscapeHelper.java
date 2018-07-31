package com.neo.security.certpath.store;

import java.net.MalformedURLException;
import java.net.Socket;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSocketFactory;
import netscape.ldap.LDAPUrl;

import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509LDAPCertStoreParameters;

class LDAPNetscapeHelper implements LDAPHelper.LDAPHelperSPI{

	private final static LDAPEntry EMPTY_ATTRIBUTES = new LDAPEntry();
	
	private final static byte[][] BB0 = new byte[0][];

	private X509LDAPCertStoreParameters params = null;
	
	public LDAPNetscapeHelper(X509LDAPCertStoreParameters params)
	{
		this.params = params;
	}
	
	private LDAPConnection connectLDAP() throws LDAPException
	{
		System.out.println("connect to " +  params.getLdapURL());
		
		LDAPUrl url;
		try {
			url = new LDAPUrl(params.getLdapURL());
		} catch (MalformedURLException e) {
			throw new LDAPException(e.getMessage());
		}
		
		LDAPConnection ldapConn = new LDAPConnection(new LDAPSocketFactoryImpl());
		ldapConn.connect(url.getHost(), url.getPort() == -1 ? 389 : url.getPort() );
		ldapConn.setConnectTimeout(30*1000);
		
		return ldapConn;
	}
	

	public List engineGetLdapAttributeValues(String dn, String[] requestedAttributes) throws StoreException
	{
		LDAPConnection ctx = null;
		try {
			ctx = connectLDAP();

			
//			if (requestedAttributes[0].equals("cACertificate") || requestedAttributes[1].equals("cACertificate"))
//				(new Exception("")).printStackTrace();
			ArrayList valueList = new ArrayList();

			LDAPEntry entry = null;
			try {
				entry = ctx.read( dn, requestedAttributes);
				
			} catch ( LDAPException e) {
				// name does not exist on this LDAP server
				// treat same as not attributes found
				entry = EMPTY_ATTRIBUTES;
			}

			for (int i=0; i < requestedAttributes.length ; i++) {
				String attrId = requestedAttributes[i];
				LDAPAttribute attr = entry.getAttribute(attrId);
				byte[][] values = getAttributeValues(attr);
				for(int v = 0; v < values.length ; v++)
					valueList.add(values[v]);
			}

			System.out.println("downloaded dn: " + valueList.size() + " >> " + (dn.length() > 50 ? dn.substring(0, 50) + "..." : dn) + "?" + requestedAttributes[0]);

			return valueList;
		}
		catch (LDAPException e)
		{
			// skip exception, unfortunately if an attribute type is not
			// supported an exception is thrown

			//			e.printStackTrace();

//			e.printStackTrace();
			
			throw new StoreException("cannot connect to " + params.getLdapURL(),e);
			
//			return new ArrayList();
//			throw new StoreException("LDAP Error. ",e);
		}
		finally
		{
			try
			{
				if (null != ctx)
				{
					ctx.disconnect();
				}
			}
			catch (Exception e)
			{
			}
		}
	}


	private byte[][] getAttributeValues(LDAPAttribute attr) 
			throws LDAPException {
		byte[][] values;
		if (attr == null) {
			values = BB0;
		} else {
			Enumeration en = attr.getByteValues();
			System.out.println("attribute size: " + attr.size());
			values = new byte[attr.size()][];
			int i=0;
			while(en.hasMoreElements())
			{
				values[i] = (byte[])en.nextElement();
				System.out.println("downloaded length: " + values[i].length);
				i++;
			}
		}
	
		return values;
	}
	
	
	public class LDAPSocketFactoryImpl implements LDAPSocketFactory
	{
		public java.net.Socket makeSocket(final String host, final int port) throws LDAPException
		{
			
			return (java.net.Socket) AccessController.doPrivileged(new PrivilegedAction()
	        {
	            public Object run()
	            {
	            	
	    			Socket soc = null;
	    			try
	    			{
	    				soc = new Socket(host, port);
	    				soc.setSoTimeout(1000 * 30);
	    			}
	    			catch(Exception e)
	    			{
	    				if(soc != null){
	    					try{soc.close();}catch(Exception ex){}
	    				}
	    				throw new IllegalStateException("Cannot create java.net.Socket...");
	    			}
	    			return soc;
	            }
	        });
		}
	}
}
