package com.neo.security.certpath;

import java.security.cert.CertStoreParameters;
import java.security.cert.LDAPCertStoreParameters;

import com.neo.security.x509.X509StoreParameters;

/**
 * An expanded set of parameters for an LDAPCertStore
 */
public class X509HttpCertStoreParameters
    implements X509StoreParameters, CertStoreParameters
{

    private String url;

    public static class Builder
    {
    	private String url;

        public Builder()
        {
            this("http://localhost:8080");
        }

        public Builder(String url)
        {
            this.url = url;
        }

  
        public String getUrl() {
    		return url;
    	}

    	public void setUrl(String url) {
    		this.url = url;
    	}
    	
        public X509HttpCertStoreParameters build()
        {
             if (url == null)
            {
                throw new IllegalArgumentException(
                    "Necessary parameters not specified.");
            }
             
            return new X509HttpCertStoreParameters(this);
        }
    }

    private X509HttpCertStoreParameters(Builder builder)
    {
        this.url = builder.url;
    }

    public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	/**
     * Returns a clone of this object.
     */
    public Object clone()
    {
        return this;
    }

    public boolean equal(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof X509HttpCertStoreParameters))
        {
            return false;
        }

        X509HttpCertStoreParameters params = (X509HttpCertStoreParameters)o;
        
        return checkField(url, params.url);
    }

    private boolean checkField(Object o1, Object o2)
    {
        if (o1 == o2)
        {
            return true;
        }

        if (o1 == null)
        {
            return false;
        }

        return o1.equals(o2);
    }

    public int hashCode()
    {
        int hash = 0;

        hash = addHashCode(hash, url);
        
        return hash;
    }

    private int addHashCode(int hashCode, Object o)
    {
        return (hashCode * 29) + (o == null ? 0 : o.hashCode());
    }
 
    public static X509HttpCertStoreParameters getInstance(X509HttpCertStoreParameters params)
    {
        String url = params.getUrl();
        X509HttpCertStoreParameters _params = new Builder(url).build();
        return _params;
    }
}
