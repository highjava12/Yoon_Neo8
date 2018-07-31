package com.neo.security.asn1.pkcs;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.x509.AlgorithmIdentifier;

public class KeyDerivationFunc
    extends AlgorithmIdentifier
{
    KeyDerivationFunc(
        ASN1Sequence  seq)
    {
        super(seq);
    }
    
    KeyDerivationFunc(
        DERObjectIdentifier id,
        ASN1Encodable       params)
    {
        super(id, params);
    }
}
