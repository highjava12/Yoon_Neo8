package com.neo.security.asn1.pkcs;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1Set;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERTaggedObject;

public class SafeBag
    extends ASN1Encodable
{
    DERObjectIdentifier         bagId;
    DERObject                   bagValue;
    ASN1Set                     bagAttributes;

    public SafeBag(
        DERObjectIdentifier     oid,
        DERObject               obj)
    {
        bagId = oid;
        bagValue = obj;
        bagAttributes = null;
    }

    public SafeBag(
        DERObjectIdentifier     oid,
        DERObject               obj,
        ASN1Set                 bagAttributes)
    {
        bagId = oid;
        bagValue = obj;
        this.bagAttributes = bagAttributes;
    }

    public SafeBag(
        ASN1Sequence    seq)
    {
        bagId = (DERObjectIdentifier)seq.getObjectAt(0);
        bagValue = ((DERTaggedObject)seq.getObjectAt(1)).getObject();
        if (seq.size() == 3)
        {
            bagAttributes = (ASN1Set)seq.getObjectAt(2);
        }
    }

    public DERObjectIdentifier getBagId()
    {
        return bagId;
    }

    public DERObject getBagValue()
    {
        return bagValue;
    }

    public ASN1Set getBagAttributes()
    {
        return bagAttributes;
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(bagId);
        v.add(new DERTaggedObject(0, bagValue));

        if (bagAttributes != null)
        {
            v.add(bagAttributes);
        }

        return new DERSequence(v);
    }
}
