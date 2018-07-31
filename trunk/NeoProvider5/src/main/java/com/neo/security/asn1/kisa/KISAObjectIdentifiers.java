package com.neo.security.asn1.kisa;

import com.neo.security.asn1.DERObjectIdentifier;



public interface KISAObjectIdentifiers
{
	public static final DERObjectIdentifier id_KISA = new DERObjectIdentifier("1.2.410.200004");
	public static final DERObjectIdentifier id_npki = new DERObjectIdentifier(id_KISA + ".10");
	
	public static final DERObjectIdentifier id_attribute = new DERObjectIdentifier(id_npki + ".1");
	public static final DERObjectIdentifier id_kisa_identifyData = new DERObjectIdentifier(id_attribute + ".1");
	public static final DERObjectIdentifier id_VID = new DERObjectIdentifier(id_kisa_identifyData + ".1");
	public static final DERObjectIdentifier id_EncryptedVID = new DERObjectIdentifier(id_kisa_identifyData + ".2");
	public static final DERObjectIdentifier id_randomNum = new DERObjectIdentifier(id_kisa_identifyData + ".3");
		
    public static final DERObjectIdentifier id_seedCBC = new DERObjectIdentifier(id_KISA + ".1.4");
    public static final DERObjectIdentifier id_npki_app_cmsSeed_wrap = new DERObjectIdentifier("1.2.410.200004.7.1.1.1");
    
    
    
    
}
