package com.neo.security.asn1.vid;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERBitString;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERPrintableString;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERTaggedObject;

public class HashContent
    extends ASN1Encodable
{
	DERPrintableString      idn;
	DERBitString      randomNum;
    
    public static HashContent getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static HashContent getInstance(
        Object obj)
    {
        if (obj instanceof HashContent)
        {
            return (HashContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new HashContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    private HashContent(
        ASN1Sequence seq)
    {
    	if (seq.size() < 2) {
			throw new IllegalArgumentException("unknown object in factory: size = " + seq.size());
		}
        
    	Enumeration en = seq.getObjects();

    	idn = DERPrintableString.getInstance(en.nextElement());
    	randomNum = DERBitString.getInstance(en.nextElement());
    	
    }

    public HashContent(DERPrintableString idn, DERBitString randomNum)
    {
    	this.idn = idn;
    	this.randomNum = randomNum;
    }
    
	public DERPrintableString getIdn() {
		return idn;
	}

	public DERBitString getRandomNum() {
		return randomNum;
	}

	/**
     * <pre>
			HashContent ::= SEQUENCE {
					idn PrintableString,
					randomNum BIT STRING
			}
     *
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(idn);
        v.add(randomNum);
        
        return new DERSequence(v);
    }
 
    
    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}



