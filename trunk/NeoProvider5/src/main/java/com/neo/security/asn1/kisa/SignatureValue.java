package com.neo.security.asn1.kisa;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.DEROctetString;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.x509.AlgorithmIdentifier;

public class SignatureValue
    extends ASN1Encodable
{
    private SignatureToken[] toBeSigned;
    private AlgorithmIdentifier signatureAlgorithm;
    private SignerAndSerialNumber signerAndSerialNumber;
    private ASN1OctetString signature;
    
    
    public SignatureValue(SignatureToken[] toBeSigneds,
    		String signatureAlgorithm,
    		SignerAndSerialNumber signerAndSerialNumber,
    		byte[]  signature )
    {
    	this.toBeSigned = toBeSigneds;
    	
    	this.signatureAlgorithm = new AlgorithmIdentifier(new DERObjectIdentifier(signatureAlgorithm));
    	this.signerAndSerialNumber = signerAndSerialNumber;
    	this.signature = new DEROctetString(signature);
    }
    
    public SignatureValue(ASN1Sequence toBeSigneds,
    		AlgorithmIdentifier signatureAlgorithm,
    		SignerAndSerialNumber signerAndSerialNumber,
    		DEROctetString  signature )
    {
    	this.toBeSigned = new SignatureToken[toBeSigneds.size()];
    	for(int i=0; i < toBeSigneds.size() ;i++)
    		this.toBeSigned[i] = SignatureToken.getInstance(toBeSigneds.getObjectAt(i));
    	
    	this.signatureAlgorithm = signatureAlgorithm;
    	this.signerAndSerialNumber = signerAndSerialNumber;
    	this.signature = signature;
    }
    
    private SignatureValue(ASN1Sequence seq)
    {
    	ASN1Sequence toBeSigned = ASN1Sequence.getInstance(seq.getObjectAt(0));
    	this.toBeSigned = new SignatureToken[toBeSigned.size()];
    	
    	for(int i=0; i < toBeSigned.size() ;i++)
    		this.toBeSigned[i] = SignatureToken.getInstance(toBeSigned.getObjectAt(i));
    	
    	signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
    	signerAndSerialNumber = SignerAndSerialNumber.getInstance(seq.getObjectAt(2));
    	signature = DEROctetString.getInstance(seq.getObjectAt(3));
    	
    }

    public static SignatureValue getInstance(Object o)
    {
        if (o instanceof SignatureToken)
        {
            return (SignatureValue)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new SignatureValue((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

	public SignatureToken[] getToBeSigned() {
		return toBeSigned;
	}

	public AlgorithmIdentifier getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public SignerAndSerialNumber getSignerAndSerialNumber() {
		return signerAndSerialNumber;
	}

	public ASN1OctetString getSignature() {
		return signature;
	}

	public DERObject toASN1Object()
    {

    	ASN1EncodableVector v = new ASN1EncodableVector();
    	for(int i=0; i < toBeSigned.length ;i++)
    		v.add(toBeSigned[i]);

        v = new ASN1EncodableVector();
    	v.add(new DERSequence(v));
    	
        v.add(signatureAlgorithm);
        v.add(signerAndSerialNumber);
        v.add(signature);

        return new DERSequence(v);
    }
}
