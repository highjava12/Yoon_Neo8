package com.neo.security.certpath.store;

import com.neo.security.x509.X509StoreParameters;

/**
 * This class contains a collection for collection based <code>X509Store</code>s.
 * 
 * @see com.kica.security.x509.ncrypto.x509.X509Store
 * 
 */
public class X509DirectoryStoreParameters
    implements X509StoreParameters
{
    private String  dirName;

    public X509DirectoryStoreParameters(String dirName)
    {
        if (dirName == null)
        {
            throw new NullPointerException("directory name cannot be null.");
        }
        
        this.dirName = dirName;
    }

    public Object clone()
    {
        return new X509DirectoryStoreParameters(dirName);
    }
    
    public String getDirectoryName()
    {
        return dirName;
    }
    
    public String toString()
    {
        StringBuffer sb = new StringBuffer();
        sb.append("X509DirectoryStoreParameters: [\n");
        sb.append("  Directory: " + dirName + "\n");
        sb.append("]");
        return sb.toString();
    }
}
