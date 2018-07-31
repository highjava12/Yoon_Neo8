package com.neo.security.certpath.store;

import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.net.URLDecoder;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import com.neo.security.asn1.ASN1Object;
import com.neo.security.asn1.DERIA5String;
import com.neo.security.asn1.x509.CRLDistPoint;
import com.neo.security.asn1.x509.DistributionPoint;
import com.neo.security.asn1.x509.DistributionPointName;
import com.neo.security.asn1.x509.GeneralName;
import com.neo.security.asn1.x509.GeneralNames;
import com.neo.security.bcutil.Selector;
import com.neo.security.certpath.StoreException;
import com.neo.security.certpath.util.AmFile;
import com.neo.security.provider.NeoProvider;
import com.neo.security.x509.X509CRLStoreSelector;
import com.neo.security.x509.X509CertStoreSelector;
import com.neo.security.x509.X509StoreParameters;
import com.neo.security.x509.X509StoreSpi;

/**
 * A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
 * certificate revocation lists from an LDAP directory.
 *
 * @see com.kica.security.x509.sg.openews.x509.X509Store
 */
public class X509StoreDirectory extends X509StoreSpi
{
	CertificateFactory cf;
    private String directoryName;

    public X509StoreDirectory()
    {
    	try {
			cf = CertificateFactory.getInstance("X.509", NeoProvider.PROVIDER_NAME);
		} catch (CertificateException e) {
			throw new IllegalStateException(e.getMessage());
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException(e.getMessage());
		}
    }

    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509DirectoryStoreParameters))
        {
            throw new IllegalArgumentException(
                "Initialization parameters must be an instance of "
                    + X509DirectoryStoreParameters.class.getName() + ".");
        }
        directoryName = ((X509DirectoryStoreParameters)params).getDirectoryName();
    }


    public Collection engineGetMatches(Selector selector) throws StoreException
    {
    	if (selector instanceof X509CertStoreSelector)
    		return getCertificateMatches(selector);
    	
    	if (!(selector instanceof X509CRLStoreSelector))
        {
            return Collections.EMPTY_SET;
        }
    	
        X509CRLStoreSelector xselector = (X509CRLStoreSelector)selector;
        Set set = new HashSet();
        // test only delta CRLs should be selected
        if (xselector.isDeltaCRLIndicatorEnabled())
        {
        	return Collections.EMPTY_SET;
        }
        else
        {
//        	File fd = new File(this.directoryName + File.separator + getCRLName(xselector));
        	
        	ArrayList files = getFiles(getCRLName(xselector));
        	
        	String fileName = null;
        	for(int i=0; i < files.size();i++)
        	{
        		AmFile fd = (AmFile)files.get(i);
        		
//    			System.out.println("FIND: " + fd.getName());
        		if (fd.exists())
	        	{
	        		FileInputStream is = null;
	        		try {
	        			
//	        			System.out.println("READ: " + fd.getName());
	        			is = fd.getFileInputStream();
	        			
	        			X509CRL crl = (X509CRL)cf.generateCRL(is);
	
	        			if ((new Date()).getTime() < crl.getNextUpdate().getTime())
	        				set.add(crl);
	        			
	        		}catch(Exception ex)
	        		{
	        			ex.printStackTrace();
	        		}
	        		finally{
	        			if (is != null)try{is.close();}catch(IOException e){}
	        		}
	        		
	        		if (set.size() == 0)
	        			fd.delete();

	        	}
        	}
        }
        
        return set;
    }
    
    ArrayList getFiles(String name)
    {
    	ArrayList files = new ArrayList();
    	AmFile dir = new AmFile(directoryName);
    	
    	String[] names = dir.list(new CRLFilter(name));
    	
    	if (names != null)
    	{
    		for(int i=0; i < names.length ;i++)
    			files.add(new AmFile(directoryName + AmFile.separator + names[i]));
    	}
    	
    	return files;
    }
    
//    ArrayList getFiles(String name)
//    {
//    	ArrayList files = new ArrayList();
//    	
//    	//File dir = new File(directoryName);
//    	File dir = CertPathAm.getFile(directoryName);
//    	
//    	//String[] names = dir.list(new CRLFilter(name));
//    	
//    	String[] names =  CertPathAm.listFiles(directoryName,  new CRLFilter(name));
//    	
//    	if (names != null)
//    	{
//    		for(int i=0; i < names.length ;i++)
//    			//files.add(new File(directoryName + File.separator + names[i]));
//    			files.add(CertPathAm.getFile(directoryName + File.separator + names[i]));
//    	}
//    	
//    	return files;
//    }
    
    class CRLFilter implements FilenameFilter
    {
    	String search;
    	public CRLFilter(String search)
    	{
    		this.search = search;
    	}
		public boolean accept(java.io.File dir, String name) 
		{
			if (name.startsWith(search) && name.endsWith(".crl"))
				return true;
			
			return false;
		}
    	
    }

    public static String getCRLName(X509CRLStoreSelector xselector) throws StoreException
    {

        CRLDistPoint crldp = null;
        try
        {
            crldp = CRLDistPoint.getInstance(ASN1Object.fromByteArray(xselector.getIssuingDistributionPoint()));
        }
        catch (Exception e)
        {
            throw new StoreException("CRL distribution point extension could not be read.",e);
        }
        
        return getCRLName(crldp);
        
    }
    

    public static String getCRLName(CRLDistPoint crldp) throws StoreException
    {
        DistributionPoint dps[] = null;
        try
        {
            dps = crldp.getDistributionPoints();
        }
        catch (Exception e)
        {
        	 throw new StoreException("Distribution points could not be read.",e);
        }
        
        for (int i = 0; i < dps.length; i++)
        {
        	String name = getCRLName(dps[i]);
        	
        	if (name != null)
        		return name;
        	
        }
    
        return null;
    }
    
    public static String getCRLName(DistributionPoint dp) throws StoreException
    {
            DistributionPointName dpn = dp.getDistributionPoint();
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
                            
//                            if (location.startsWith("ldap://"))
//                            {
                            	return getFileNameFromLocation(location);
//                            }
                        }
                    }
                }
            }

            return null;
    }
    
    static String getFileNameFromLocation(String location)
    {
        try
        {
        	String lowerLocation = location.toLowerCase();
            if (lowerLocation.startsWith("ldap://"))
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
            else if (lowerLocation.startsWith("http://") || lowerLocation.startsWith("https://"))
            {
            	return location.substring(location.indexOf("//") + 2).replaceAll("/", "_");
            }
            
            return null;
        }
        catch (Exception e)
        {
            throw new StoreException("Exception adding X.509 stores.");
        }
    }

    
    
    private Collection getCertificateMatches(Selector selector) throws StoreException
    {
        X509CertStoreSelector xselector = (X509CertStoreSelector)selector;
        
        Set set = new HashSet();

        String certName = getCertificateName(xselector);
        if (certName == null)
        	return Collections.EMPTY_SET;
        
        
    	AmFile fd = new AmFile(this.directoryName + AmFile.separator + certName);
		
//    	System.out.println("FIND: " + fd.getName());
    	
    	if (fd.exists())
    	{
    		FileInputStream is = null;
    		try {
//    			System.out.println("READ: " + fd.getName());
    			//is = new FileInputStream(fd);
    			is = fd.getFileInputStream();
    			
    			set.add(cf.generateCertificate(is));
    			
    		}catch(Exception ex)
    		{

    		}finally{
    			if (is != null)try{is.close();}catch(IOException e){}
    		}
    		
    		if (set.size() == 0)
    		{
    			fd.delete();
    		}
    	}
    	
        
        return set;
    }
    
    public static String getCertificateName(X509CertStoreSelector xselector) throws StoreException
    {
    	String subjectDN = xselector.getSubjectAsString();
    	
    	if (subjectDN == null && xselector.getCertificate() != null)
    	{
    		return xselector.getCertificate().getSubjectDN().getName() + ".der";
    	}
    	
    	return subjectDN + ".der";
    }
    
//    public void saveCRL(byte[] crldp,byte[] crl)
//    {
//    	File fd = new File(this.directoryName + File.separator + cert.getSubjectDN().getName());
//		FileOutputStream out = null;
//		try {
//			
//			out = new FileOutputStream(fd);
//			
//			out.write(cert.getEncoded());
//			
//		}catch(Exception ex)
//		{
//			
//		}finally{
//			if (out != null)try{out.close();}catch(IOException e){}
//		}
//    }
}
