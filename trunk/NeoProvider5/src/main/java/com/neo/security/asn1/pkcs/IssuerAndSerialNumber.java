package com.neo.security.asn1.pkcs;

import java.math.BigInteger;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.x509.X509Name;

public class IssuerAndSerialNumber
    extends ASN1Encodable
{
    X509Name    name;
    DERInteger  certSerialNumber;

    public static IssuerAndSerialNumber getInstance(
        Object  obj)
    {
        if (obj instanceof IssuerAndSerialNumber)
        {
            return (IssuerAndSerialNumber)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new IssuerAndSerialNumber((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public IssuerAndSerialNumber(
        ASN1Sequence    seq)
    {
        name = X509Name.getInstance(seq.getObjectAt(0));
        certSerialNumber = (DERInteger)seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(
        X509Name    name,
        BigInteger  certSerialNumber)
    {
        this.name = name;
        this.certSerialNumber = new DERInteger(certSerialNumber);
    }

    public IssuerAndSerialNumber(
        X509Name    name,
        DERInteger  certSerialNumber)
    {
        this.name = name;
        this.certSerialNumber = certSerialNumber;
    }

    public X509Name getName()
    {
        return name;
    }

    public DERInteger getCertificateSerialNumber()
    {
        return certSerialNumber;
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(name);
        v.add(certSerialNumber);

        return new DERSequence(v);
    }
}
