package com.neo.security.asn1.kisa;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.x509.X509Name;

public class SignerAndSerialNumber
    extends ASN1Encodable
{
    private X509Name issuer;
    private DERInteger serialNumber;

    public SignerAndSerialNumber(String name, int serialNumber)
    {
    	this.issuer = new X509Name(name);
    	this.serialNumber = new DERInteger(serialNumber);
    }
    
    public SignerAndSerialNumber(X509Name name, DERInteger serialNumber)
    {
    	this.issuer = name;
    	this.serialNumber = serialNumber;
    }
    
    
    private SignerAndSerialNumber(ASN1Sequence seq)
    {
    	issuer = X509Name.getInstance(seq.getObjectAt(0));
    	serialNumber = DERInteger.getInstance(seq.getObjectAt(1));
    }

    public static SignerAndSerialNumber getInstance(Object o)
    {
        if (o instanceof SignatureToken)
        {
            return (SignerAndSerialNumber)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new SignerAndSerialNumber((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

 
    public X509Name getIssuer() {
		return issuer;
	}

	public DERInteger getSerialNumber() {
		return serialNumber;
	}

	public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(issuer);
        v.add(serialNumber);

        return new DERSequence(v);
    }
}
