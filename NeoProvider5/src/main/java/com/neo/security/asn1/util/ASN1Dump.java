package com.neo.security.asn1.util;


import java.util.Enumeration;

import com.neo.security.asn1.ASN1OctetString;
import com.neo.security.asn1.ASN1Sequence;
import com.neo.security.asn1.ASN1Set;
import com.neo.security.asn1.BERConstructedOctetString;
import com.neo.security.asn1.BERConstructedSequence;
import com.neo.security.asn1.BERSequence;
import com.neo.security.asn1.BERSet;
import com.neo.security.asn1.BERTaggedObject;
import com.neo.security.asn1.DERBMPString;
import com.neo.security.asn1.DERBitString;
import com.neo.security.asn1.DERBoolean;
import com.neo.security.asn1.DERConstructedSequence;
import com.neo.security.asn1.DERConstructedSet;
import com.neo.security.asn1.DEREncodable;
import com.neo.security.asn1.DERGeneralizedTime;
import com.neo.security.asn1.DERIA5String;
import com.neo.security.asn1.DERInteger;
import com.neo.security.asn1.DERNull;
import com.neo.security.asn1.DERObject;
import com.neo.security.asn1.DERObjectIdentifier;
import com.neo.security.asn1.DEROctetString;
import com.neo.security.asn1.DERPrintableString;
import com.neo.security.asn1.DERSequence;
import com.neo.security.asn1.DERSet;
import com.neo.security.asn1.DERT61String;
import com.neo.security.asn1.DERTaggedObject;
import com.neo.security.asn1.DERUTCTime;
import com.neo.security.asn1.DERUTF8String;
import com.neo.security.asn1.DERUnknownTag;
import com.neo.security.asn1.DERVisibleString;
import com.neo.security.encoders.Hex;

public class ASN1Dump
{
    private static final String  TAB = "    ";

    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the DERObject to be dumped out.
     */
    static String _dumpAsString(
        String      indent,
        DERObject   obj)
    {
        if (obj instanceof ASN1Sequence)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Sequence)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERConstructedSequence)
            {
                buf.append("BER ConstructedSequence");
            }
            else if (obj instanceof DERConstructedSequence)
            {
                buf.append("DER ConstructedSequence");
            }
            else if (obj instanceof BERSequence)
            {
                buf.append("BER Sequence");
            }
            else if (obj instanceof DERSequence)
            {
                buf.append("DER Sequence");
            }
            else
            {
                buf.append("Sequence");
            }

            buf.append(System.getProperty("line.separator"));

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null || o.equals(new DERNull()))
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(System.getProperty("line.separator"));
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof DERTaggedObject)
        {
            StringBuffer    buf = new StringBuffer();
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERTaggedObject)
            {
                buf.append("BER Tagged [");
            }
            else
            {
                buf.append("Tagged [");
            }

            DERTaggedObject o = (DERTaggedObject)obj;

            buf.append(Integer.toString(o.getTagNo()));
            buf.append(']');

            if (!o.isExplicit())
            {
                buf.append(" IMPLICIT ");
            }

            buf.append(System.getProperty("line.separator"));

            if (o.isEmpty())
            {
                buf.append(tab);
                buf.append("EMPTY");
                buf.append(System.getProperty("line.separator"));
            }
            else
            {
                buf.append(_dumpAsString(tab, o.getObject()));
            }

            return buf.toString();
        }
        else if (obj instanceof DERConstructedSet)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("ConstructedSet");
            buf.append(System.getProperty("line.separator"));

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(System.getProperty("line.separator"));
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof BERSet)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("BER Set");
            buf.append(System.getProperty("line.separator"));

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(System.getProperty("line.separator"));
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof DERSet)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("DER Set");
            buf.append(System.getProperty("line.separator"));

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(System.getProperty("line.separator"));
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof DERObjectIdentifier)
        {
            return indent + "ObjectIdentifier(" + ((DERObjectIdentifier)obj).getId() + ")" + System.getProperty("line.separator");
        }
        else if (obj instanceof DERBoolean)
        {
            return indent + "Boolean(" + ((DERBoolean)obj).isTrue() + ")" + System.getProperty("line.separator");
        }
        else if (obj instanceof DERInteger)
        {
            return indent + "Integer(" + ((DERInteger)obj).getValue() + ")" + System.getProperty("line.separator");
        }
        else if (obj instanceof BERConstructedOctetString)
        {
            return indent + "BER Constructed Octet String" + "[" + ((ASN1OctetString)obj).getOctets().length + "] " + System.getProperty("line.separator");
        }
        else if (obj instanceof DEROctetString)
        {
            return indent + "DER Octet String" + "[" + ((ASN1OctetString)obj).getOctets().length + "] " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERBitString)
        {
            return indent + "DER Bit String" + "[" + ((DERBitString)obj).getBytes().length + ", " + ((DERBitString)obj).getPadBits() + "] " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERIA5String)
        {
            return indent + "IA5String(" + ((DERIA5String)obj).getString() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERUTF8String)
        {
            return indent + "UTF8String(" + ((DERUTF8String)obj).getString() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERPrintableString)
        {
            return indent + "PrintableString(" + ((DERPrintableString)obj).getString() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERVisibleString)
        {
            return indent + "VisibleString(" + ((DERVisibleString)obj).getString() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERBMPString)
        {
            return indent + "BMPString(" + ((DERBMPString)obj).getString() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERT61String)
        {
            return indent + "T61String(" + ((DERT61String)obj).getString() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERUTCTime)
        {
            return indent + "UTCTime(" + ((DERUTCTime)obj).getTime() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERGeneralizedTime)
        {
            return indent + "GeneralizedTime(" + ((DERGeneralizedTime)obj).getTime() + ") " + System.getProperty("line.separator");
        }
        else if (obj instanceof DERUnknownTag)
        {
            return indent + "Unknown " + Integer.toString(((DERUnknownTag)obj).getTag(), 16) + " " + new String(Hex.encode(((DERUnknownTag)obj).getData())) + System.getProperty("line.separator");
        }
        else
        {
            return indent + obj.toString() + System.getProperty("line.separator");
        }
    }

    /**
     * dump out a DER object as a formatted string
     *
     * @param obj the DERObject to be dumped out.
     */
    public static String dumpAsString(
        Object   obj)
    {
        if (obj instanceof DERObject)
        {
            return _dumpAsString("", (DERObject)obj);
        }
        else if (obj instanceof DEREncodable)
        {
            return _dumpAsString("", ((DEREncodable)obj).getDERObject());
        }

        return "unknown object type " + obj.toString();
    }
}
