package com.neo.security.certpath;

public class CollectorParameter
{
	String ldapAddress = null;
	int ldapPort = 389;
	
	String cachePath = null;
	
	public CollectorParameter()
	{
		
	}

	public String getLdapAddress() {
		return ldapAddress;
	}

	public void setLdapAddress(String ldapAddress) {
		this.ldapAddress = ldapAddress;
	}

	public int getLdapPort() {
		return ldapPort;
	}

	public void setLdapPort(int ldapPort) {
		this.ldapPort = ldapPort;
	}

	public String getCachePath() {
		return cachePath;
	}

	public void setCachePath(String cachePath) {
		this.cachePath = cachePath;
	}
	
}
