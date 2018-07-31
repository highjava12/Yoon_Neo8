package com.neo.security.asn1.vid;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERTaggedObject;
import com.neo.security.asn1.x509.AlgorithmIdentifier;

public class VID
    extends ASN1Encodable
{
	AlgorithmIdentifier      hashAlg;
	ASN1OctetString      virtualID;
    
    public static VID getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static VID getInstance(
        Object obj)
    {
        if (obj instanceof VID)
        {
            return (VID)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new VID((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    private VID(
        ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        if (en.hasMoreElements()) {
			hashAlg = AlgorithmIdentifier.getInstance(en.nextElement());
		}
        
        if (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	virtualID = ASN1OctetString.getInstance(tObj, true);
                break;

            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }

        }
    	
    }

    public VID(AlgorithmIdentifier hashAlg, ASN1OctetString virtualID)
    {
    	this.hashAlg = hashAlg;
    	this.virtualID = virtualID;
    }
    
	public AlgorithmIdentifier getHashAlg() {
		return hashAlg;
	}

	public ASN1OctetString getVirtualID() {
		return virtualID;
	}

	/**
     * <pre>
			VID ::= SEQUENCE {
					hashAlg HashAlgorithm,
					virtualID [0] OCTET STRING }
     *
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(hashAlg);
        addOptional(v, 0, virtualID);

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



