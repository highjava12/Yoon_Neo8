package com.neo.security.asn1.ocsp;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.x509.X509Name;

public class ServiceLocator
    extends ASN1Encodable
{
    X509Name    issuer;
    DERObject    locator;

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ServiceLocator ::= SEQUENCE {
     *     issuer    Name,
     *     locator   AuthorityInfoAccessSyntax OPTIONAL }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(issuer);

        if (locator != null)
        {
            v.add(locator);
        }

        return new DERSequence(v);
    }
}
