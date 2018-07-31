package com.neo.security.certpath;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.x500.X500Principal;

import com.neo.security.asn1.x509.X509Name;


public class CRLSelectorAccessManager
{
//	public static security.util.Debug getDebug(String name)
//    {
//		final String namef = name;
//
//		return (security.util.Debug) AccessController
//		         .doPrivileged(new PrivilegedAction()
//		         {
//		             public Object run()
//		             {
//		            	return security.util.Debug.getInstance(namef);
//		            	 //return security.util.Debug.getInstance(namef);
//		             }
//		         });	
//    }
    
//    public static security.util.DerInputStream getDerInputStream(byte[] data) throws IOException
//    {
//    	final byte[] dataf = data;
//    	try {
//			return (security.util.DerInputStream) AccessController
//			         .doPrivileged(new PrivilegedExceptionAction()
//			         {
//			             public Object run() throws Exception
//			             {
//			         		return new security.util.DerInputStream(dataf);	
//			             }
//			         });
//		} catch (PrivilegedActionException e) {
//
//			throw (IOException)e.getCause();
//		}
//    }
//    
//    public static security.x509.CRLNumberExtension getCRLNumberExtension(Boolean booleanValue, byte[] data) throws IOException
//    {
//    	final Boolean booleanValuef = booleanValue;
//    	final byte[] dataf = data;
//    	
//    	try {
//			return (security.x509.CRLNumberExtension) AccessController
//			         .doPrivileged(new PrivilegedExceptionAction()
//			         {
//			             public Object run() throws Exception
//			             {
//			         		return new security.x509.CRLNumberExtension(booleanValuef, dataf);	
//			             }
//			         });
//		} catch (PrivilegedActionException e) {
//			throw (IOException)e.getCause();
//		}
//    }
    
    
//    public static security.x509.X500Name getX500Name(String name, String type)
//    {
//    	final String namef = name;
//    	final String typef = type;
//    	
//    	return (security.x509.X500Name) AccessController
//		         .doPrivileged(new PrivilegedAction()
//		         {
//		             public Object run()
//		             {
//		            	 try
//		         		{
//		             		return new security.x509.X500Name(namef, typef);	
//		         		}
//		         		catch (Exception e)
//		         		{
//		         			e.printStackTrace();
//		         			return null;
//		         		}
//		             }
//		         });
//    }
    
    public static X500Principal getX500Principal(String name, String type) throws IOException
    {
		return new X500Principal(new X509Name(type.equals("RFC2253") ? true : false, name).getEncoded());
    }

    public static X500Principal getX500Principal(byte[] name) throws IOException
    {
			return new X500Principal(name);
    }

    
//    public static security.x509.X500Name getX500Name(String name, String type) throws IOException
//    {
//    	final String namef = name;
//    	final String typef = type;
//    	
//    	try {
//			return (security.x509.X500Name) AccessController
//			         .doPrivileged(new PrivilegedExceptionAction()
//			         {
//			             public Object run() throws Exception
//			             {
//			         		return new security.x509.X500Name(namef, typef);	
//			             }
//			         });
//		} catch (PrivilegedActionException e) {
//			throw (IOException)e.getCause();
//		}
//    }
    
//    public static security.x509.X500Name getX500Name(byte[] name) throws IOException
//    {
//    	final byte[] namef = name;
//    	
//    	try {
//			return (security.x509.X500Name) AccessController
//			         .doPrivileged(new PrivilegedExceptionAction()
//			         {
//			             public Object run() throws Exception
//			             {
//			         		return new security.x509.X500Name(namef);	
//			             }
//			         });
//		} catch (PrivilegedActionException e) {
//			throw (IOException)e.getCause();
//		}
//    }
}
