package com.neo.security.asn1.crmf;

import com.neo.security.asn1.ASN1Choice;
import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERBoolean;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERTaggedObject;

public class PKIArchiveOptions
    extends ASN1Encodable
    implements ASN1Choice
{
    private int tagNo;
    private ASN1Encodable obj;

    private PKIArchiveOptions(ASN1TaggedObject tagged)
    {
        tagNo = tagged.getTagNo();
        switch (tagNo)
        {
        case 0:
            obj = EncryptedKey.getInstance(tagged);
            break;
        case 1:
            obj = ASN1OctetString.getInstance(tagged, false);
            break;
        case 2:
        	obj = DERBoolean.getInstance(tagged, false);
            break;
        default:
            throw new IllegalArgumentException("unknown tag: " + tagNo);
        }
    }

    public PKIArchiveOptions(EncryptedKey encryptedKey)
    {
    	tagNo = 0;
    	obj = encryptedKey;
    }
    
    public static PKIArchiveOptions getInstance(Object o)
    {
        if (o instanceof PKIArchiveOptions)
        {
            return (PKIArchiveOptions)o;
        }

        if (o instanceof ASN1TaggedObject)
        {
            return new PKIArchiveOptions((ASN1TaggedObject)o);
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
		PKIArchiveOptions ::= CHOICE {
			encryptedPrivKey [0] EncryptedKey,
			-- the actual value of the private key
			keyGenParameters [1] KeyGenParameters,
			-- parameters which allow the private key to be re-generated
			archiveRemGenPrivKey [2] BOOLEAN }
			-- set to TRUE if sender wishes receiver to archive the private
			-- key of a key pair which the receiver generates in response to
			-- this request; set to FALSE if no archival is desired.
     */
    
    public DERObject toASN1Object()
    {
        return new DERTaggedObject(false, tagNo, obj);
    }
}
