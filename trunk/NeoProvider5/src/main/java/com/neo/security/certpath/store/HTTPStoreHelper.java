package com.neo.security.certpath.store;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;

import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.X509HttpCertStoreParameters;

public class HTTPStoreHelper {
	
	X509HttpCertStoreParameters params = null;
	
	public HTTPStoreHelper(X509HttpCertStoreParameters params)
	{
		this.params = params;

	}
	
	public byte[] downloadResource() throws StoreException
    {
		return downloadResource(params.getUrl());
    }
	
    public byte[] downloadResource(String urls) throws StoreException
    {
    	java.net.URL url = null;
    	try {
			url = new java.net.URL(urls);
		} catch (MalformedURLException e) {
			throw new StoreException("Malformed URL!", e);
		}
    	
    	HttpURLConnection con = null;
		try {
			con = (HttpURLConnection)url.openConnection();
			
			doPrivilegedConnect(con);
			
	    	InputStream is = con.getInputStream();
				
	    	byte[] buffer = con.getContentLength() > 0 ?  new byte[con.getContentLength()] : new byte[is.available()];
	    	
	    	ByteArrayOutputStream out = new ByteArrayOutputStream(con.getContentLength() > 0 ? con.getContentLength() : is.available());
	    	
	    	int readCount = -1;
	    	while((readCount = is.read(buffer)) >= 0)
	    	{
	    		out.write(buffer,0,readCount);
	    	}
	    	
	    	return out.toByteArray();
		}
		catch (IOException e) 
		{
			throw new StoreException("Communication Error",e);
		}
		catch ( AccessControlException e)
		{
			throw new StoreException("IllegalState Error",e);
		}
			finally 
		{
			if (con != null) con.disconnect();
		}

    }
    
	public void doPrivilegedConnect(HttpURLConnection conn) throws AccessControlException
	{
		final HttpURLConnection fconn = conn;
	
		AccessController
	            .doPrivileged(new PrivilegedAction()
	            {
	                public Object run()
	                {
	                	
	                    try {
							fconn.connect();
						} catch (IOException e) {
							AccessControlException ex = new AccessControlException(e.getMessage());
							ex.initCause(e);
							throw ex;
						}
	                    return null;
	                }
	            });
	}
}
