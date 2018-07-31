package com.neo.security.asn1.vid;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERTaggedObject;
import com.neo.security.asn1.DERUTF8String;
import com.neo.security.asn1.crmf.AttributeTypeAndValue;

public class IdentityData
    extends ASN1Encodable
{
	DERUTF8String      realName;
	AttributeTypeAndValue[]      userInfo;
    
    public static IdentityData getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static IdentityData getInstance(
        Object obj)
    {
        if (obj instanceof IdentityData)
        {
            return (IdentityData)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new IdentityData((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    private IdentityData(
        ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        if (en.hasMoreElements()) {
        	realName = DERUTF8String.getInstance(en.nextElement());
		}
        
        if (en.hasMoreElements())
        {
        	ASN1Sequence atts = (ASN1Sequence)en.nextElement();
        	
        	if (atts.size() < 1)
        		throw new IllegalArgumentException("there is no userInfo in IdentityData");
        	
        	userInfo = new AttributeTypeAndValue[atts.size()];

        	for(int i=0; i < atts.size() ;i++)
        		userInfo[i] = AttributeTypeAndValue.getInstance(atts.getObjectAt(i));
        }
    	
    }

    public IdentityData(DERUTF8String realName, AttributeTypeAndValue[] userInfo)
    {
    	this.realName = realName;
    	this.userInfo = userInfo;
    }

	public DERUTF8String getRealName() {
		return realName;
	}

	public AttributeTypeAndValue[] getUserInfo() {
		return userInfo;
	}

	/**
     * <pre>
			IdentifyData ::= SEQUENCE {
				realName UTF8String,
				userInfo SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue 
						 OPTIONAL }
     *
     * </pre>
     */
	
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(realName);
        
        if (userInfo != null)
        {
	        ASN1EncodableVector v2 = new ASN1EncodableVector();
	        for(int i=0; i < userInfo.length ; i++)
	        	v2.add(userInfo[i]);
	        
	        v.add(new DERSequence(v2));
        }
        
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



