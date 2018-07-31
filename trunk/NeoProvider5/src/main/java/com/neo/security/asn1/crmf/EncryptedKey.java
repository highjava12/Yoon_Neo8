package com.neo.security.asn1.crmf;

import com.neo.security.asn1.ASN1Choice;
import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERTaggedObject;

public class EncryptedKey
    extends ASN1Encodable
    implements ASN1Choice
{
    private int tagNo = -1;
    private ASN1Encodable obj;

    private EncryptedKey(ASN1Encodable obj)
    {
    	if (obj instanceof ASN1TaggedObject)
    	{
    		ASN1TaggedObject tagged = (ASN1TaggedObject)obj;
	        tagNo = tagged.getTagNo();
	        switch (tagNo)
	        {
	        case 0:
	            this.obj = tagged.getObject();
	            break;
	        default:
	            throw new IllegalArgumentException("unknown tag: " + tagNo);
	        }
    	} else {
    		obj = EncryptedValue.getInstance(obj);
    	}
    }

    public EncryptedKey(EncryptedValue encryptedValue)
    {
    	obj = encryptedValue.getDERObject();
    }
    
    public static EncryptedKey getInstance(Object o)
    {
        if (o instanceof EncryptedKey)
        {
            return (EncryptedKey)o;
        }

        if (o instanceof ASN1Encodable)
        {
            return new EncryptedKey((ASN1Encodable)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }
    
    

    public int getType()
    {
        return tagNo;
    }

    public ASN1Encodable getObject()
    {
        return obj;
    }

    /**
		EncryptedKey ::= CHOICE {
			encryptedValue EncryptedValue,
			envelopedData [0] EnvelopedData }
			
			-- The encrypted private key MUST be placed in the envelopedData
			-- encryptedContentInfo encryptedContent OCTET STRING.
     */
    
    public DERObject toASN1Object()
    {
    	if (tagNo > 0) {
			return new DERTaggedObject(false, tagNo, obj);
		} else {
			return (DERObject)obj;
		}
    }
}
