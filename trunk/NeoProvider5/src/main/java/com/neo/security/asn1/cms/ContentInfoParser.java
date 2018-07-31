package com.neo.security.asn1.cms;

import java.io.IOException;

import com.neo.security.asn1.ASN1SequenceParser;
import com.neo.security.asn1.ASN1TaggedObjectParser;
import com.neo.security.asn1.DEREncodable;
import com.neo.security.asn1.DERObjectIdentifier;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *          contentType ContentType,
 *          content
 *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 * </pre>
 */
public class ContentInfoParser
{
    private DERObjectIdentifier contentType;
    private ASN1TaggedObjectParser content;

    public ContentInfoParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        contentType = (DERObjectIdentifier)seq.readObject();
        content = (ASN1TaggedObjectParser)seq.readObject();
    }

    public DERObjectIdentifier getContentType()
    {
        return contentType;
    }

    public DEREncodable getContent(
        int  tag)
        throws IOException
    {
        if (content != null)
        {
            return content.getObjectParser(tag, true);
        }

        return null;
    }
}
