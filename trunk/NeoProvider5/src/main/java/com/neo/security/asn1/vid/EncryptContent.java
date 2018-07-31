package com.neo.security.asn1.vid;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERBitString;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;

public class EncryptContent
    extends ASN1Encodable
{
	VID      vid;
    DERBitString     randomNum;
    
    public static EncryptContent getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EncryptContent getInstance(
        Object obj)
    {
        if (obj instanceof EncryptedVID)
        {
            return (EncryptContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new EncryptContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    private EncryptContent(
        ASN1Sequence seq)
    {
    	
    	if (seq.size() < 2) {
			throw new IllegalArgumentException("unknown object in factory: size = " + seq.size());
		}
        
    	Enumeration en = seq.getObjects();

    	vid = VID.getInstance(en.nextElement());
    	randomNum = DERBitString.getInstance(en.nextElement());
    }

    public EncryptContent(VID vid, DERBitString randomNum)
    {
    	this.vid = vid;
    	this.randomNum = randomNum;
    }
    

	public VID getVid() {
		return vid;
	}

	public DERBitString getRandomNum() {
		return randomNum;
	}

	/**
     * <pre>
		EncryptContent ::= SEQUENCE {
			vid VID,
			randomNum BIT STRING }
     *
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(vid);
        v.add(randomNum);

        return new DERSequence(v);
    }
    
}

