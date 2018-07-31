package com.neo.security.asn1.vid;

import java.util.Enumeration;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1TaggedObject;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERTaggedObject;
import com.neo.security.asn1.pkcs.IssuerAndSerialNumber;
import com.neo.security.asn1.x509.AlgorithmIdentifier;

public class EncryptedVID
    extends ASN1Encodable
{
    DERInteger      version;
    AlgorithmIdentifier     vidHashAlg;
    AlgorithmIdentifier     vidEncAlg;
    IssuerAndSerialNumber     certID;
    ASN1OctetString     encryptedVID;
    
    public static EncryptedVID getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EncryptedVID getInstance(
        Object obj)
    {
        if (obj instanceof EncryptedVID)
        {
            return (EncryptedVID)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new EncryptedVID((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    private EncryptedVID(
        ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
            	version = DERInteger.getInstance(tObj, true);
                break;
            case 1:
            	vidHashAlg = AlgorithmIdentifier.getInstance(tObj, true);
                break;
            case 2:
            	vidEncAlg = AlgorithmIdentifier.getInstance(tObj, true);
                break;
            case 3:
            	certID = IssuerAndSerialNumber.getInstance(tObj.getObject());
                break;
            case 4:
            	encryptedVID = ASN1OctetString.getInstance(tObj, true);
                break;

            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    	
    }

    public EncryptedVID(
    		DERInteger 				version ,
    		AlgorithmIdentifier     vidHashAlg,
    		AlgorithmIdentifier     vidEncAlg,
    		IssuerAndSerialNumber   certID,
    		ASN1OctetString    		encryptedVID )
    {
    	this.version = version;
    	this.vidHashAlg = vidHashAlg;
    	this.vidEncAlg = vidEncAlg;
    	this.certID = certID;
    	this.encryptedVID = encryptedVID;
    }
    
    public DERInteger getVersion() {
		return version;
	}

	public AlgorithmIdentifier getVidHashAlg() {
		return vidHashAlg;
	}

	public AlgorithmIdentifier getVidEncAlg() {
		return vidEncAlg;
	}

	public IssuerAndSerialNumber getCertID() {
		return certID;
	}

	public ASN1OctetString getEncryptedVID() {
		return encryptedVID;
	}

	/**
     * <pre>
	id-EncryptedVID OBJECT IDENTIFIER ::= { id-kisa-identifyData 2 }
	EncryptedVID ::= SEQUENCE {
		version [0] INTEGER DEFAULT 0,
		vidHashAlg [1] VIDHashAlgorithm OPTIONAL,
		vidEncAlg [2] VIDEncryptionAlgorithm,
		certID [3] IssuerAndSerialNumber,
		encryptedVID [4] OCTET STRING }
		
	VIDHashAlgorithm ::= AlgorithmIdentifier
	VIDEncryptionAlgorithm ::= AlgorithmIdentifier
	IssuerAndSerialNumber ::= SEQUENCE {
	issuer Name,
	serialNumber CertificateSerialNumber }
	EncryptContent ::= SEQUENCE {
	vid VID,
	randomNum BIT STRING }
     *
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        addOptional(v, 0, version);
        addOptional(v, 1, vidHashAlg);
        addOptional(v, 2, vidEncAlg);
        addOptional(v, 3, certID);
        addOptional(v, 4, encryptedVID);

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

