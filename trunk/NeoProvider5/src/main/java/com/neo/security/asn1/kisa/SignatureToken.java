package com.neo.security.asn1.kisa;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.DEROctetString;
import com.neo.security.asn1.DERPrintableString;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.x509.AlgorithmIdentifier;

public class SignatureToken
    extends ASN1Encodable
{
    private DERPrintableString driverName;
    private AlgorithmIdentifier hashID;
    private ASN1OctetString hashValue;

    
    public SignatureToken(String driverName, String oid, byte[] hashValue)
    {
    	this.driverName = new DERPrintableString(driverName);
    	this.hashID = new AlgorithmIdentifier(new DERObjectIdentifier(oid));
    	this.hashValue = new DEROctetString(hashValue);
    }
    
    private SignatureToken(ASN1Sequence seq)
    {
    	driverName = DERPrintableString.getInstance(seq.getObjectAt(0));
    	hashID = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
    	
    	hashValue = DEROctetString.getInstance(seq.getObjectAt(2));
    }

    public static SignatureToken getInstance(Object o)
    {
        if (o instanceof SignatureToken)
        {
            return (SignatureToken)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new SignatureToken((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public DERPrintableString getDriverName() {
		return driverName;
	}

	public AlgorithmIdentifier getHashID() {
		return hashID;
	}

	public ASN1OctetString getHashValue() {
		return hashValue;
	}

    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(driverName);
        v.add(hashID);
        v.add(hashValue);

        return new DERSequence(v);
    }
}
