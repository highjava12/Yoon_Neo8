package com.neo.security.asn1.crmf;

import com.neo.security.asn1.ASN1Encodable;
import com.neo.security.asn1.ASN1EncodableVector;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERSequence;

public class CertRequest
    extends ASN1Encodable
{
    private DERInteger certReqId;
    private CertTemplate certTemplate;
    private Controls controls;

    private CertRequest(ASN1Sequence seq)
    {
        certReqId = DERInteger.getInstance(seq.getObjectAt(0));
        certTemplate = CertTemplate.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2)
        {
            controls = Controls.getInstance(seq.getObjectAt(2));
        }
    }

    public static CertRequest getInstance(Object o)
    {
        if (o instanceof CertRequest)
        {
            return (CertRequest)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new CertRequest((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }
    
    public CertRequest()
    {
    	
    }

    public DERInteger getCertReqId()
    {
        return certReqId;
    }

    public CertTemplate getCertTemplate()
    {
        return certTemplate;
    }

    public Controls getControls()
    {
        return controls;
    }

    
    
    public void setCertReqId(DERInteger certReqId) {
		this.certReqId = certReqId;
	}

	public void setCertTemplate(CertTemplate certTemplate) {
		this.certTemplate = certTemplate;
	}

	public void setControls(Controls controls) {
		this.controls = controls;
	}

	/**
     * <pre>
     * CertRequest ::= SEQUENCE {
     *                      certReqId     INTEGER,          -- ID for matching request and reply
     *                      certTemplate  CertTemplate,  -- Selected fields of cert to be issued
     *                      controls      Controls OPTIONAL }   -- Attributes affecting issuance
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certReqId);
        v.add(certTemplate);

        if (controls != null)
        {
            v.add(controls);
        }

        return new DERSequence(v);
    }
}
