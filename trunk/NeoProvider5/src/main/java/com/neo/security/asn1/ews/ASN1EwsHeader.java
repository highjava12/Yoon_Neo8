package com.neo.security.asn1.ews;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERBoolean;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERUTF8String;

public class ASN1EwsHeader
    extends ASN1Encodable
{
	private DERInteger version;
	private DERUTF8String contentType;
	private DERObjectIdentifier encryptAlg;
	private DERObjectIdentifier macAlg;
	private DERBoolean encrypt;
	private DERBoolean compress;
	private DERBoolean script;
	private ASN1OctetString rapCode;
	private DERInteger contentLength;
	
    public ASN1EwsHeader(
    		DERInteger version,
    		DERUTF8String contentType,
    		DERObjectIdentifier encryptAlg,
    		DERObjectIdentifier macAlg,
    		DERBoolean encrypt,
    		DERBoolean compress,
    		DERBoolean script,
    		ASN1OctetString rapCode,
    		DERInteger contentLength)
    {
    	this.version = version;
    	this.contentType = contentType;
    	this.encryptAlg = encryptAlg;
    	this.macAlg = macAlg;
    	this.encrypt = encrypt;
    	this.compress = compress;
    	this.script = script;
    	this.rapCode = rapCode;
    	this.contentLength = contentLength;
    }

    public ASN1EwsHeader(
    		ASN1Sequence     seq)
    {
    	Enumeration e = seq.getObjects();
    	
        version = DERInteger.getInstance(e.nextElement());
    	contentType = DERUTF8String.getInstance(e.nextElement());
    	encryptAlg = DERObjectIdentifier.getInstance(e.nextElement());
    	macAlg = DERObjectIdentifier.getInstance(e.nextElement());
    	encrypt = DERBoolean.getInstance(e.nextElement());
    	compress = DERBoolean.getInstance(e.nextElement());
    	script = DERBoolean.getInstance(e.nextElement());
		rapCode = ASN1OctetString.getInstance(e.nextElement());
    	contentLength = DERInteger.getInstance(e.nextElement());
    }

    
	public static ASN1EwsHeader getInstance(Object obj)
    {
        if (obj instanceof ASN1EwsHeader)
        {
            return (ASN1EwsHeader)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new ASN1EwsHeader((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }

    public DERInteger getVersion()
    {
    	return version;
    }
    
	
    
    public DERUTF8String getContentType() {
		return contentType;
	}

	public DERObjectIdentifier getEncryptAlg() {
		return encryptAlg;
	}

	public DERObjectIdentifier getMacAlg() {
		return macAlg;
	}

	public DERBoolean getEncrypt() {
		return encrypt;
	}

	public DERBoolean getCompress() {
		return compress;
	}

	public DERBoolean getScript() {
		return script;
	}

	public ASN1OctetString getRapCode() {
		return rapCode;
	}

	public DERInteger getContentLength() {
		return contentLength;
	}

	
	public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(contentType);
        v.add(encryptAlg);
        v.add(macAlg);
        v.add(encrypt);
        v.add(compress);
        v.add(script);
        v.add(rapCode);
        v.add(contentLength);

        return new DERSequence(v);
    }
}
