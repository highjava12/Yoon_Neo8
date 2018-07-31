package com.neo.security.provider.digest;

import java.security.MessageDigest;


public class JDKMessageDigest
    extends MessageDigest
{
	Digest  digest;

    protected JDKMessageDigest(
    		Digest  digest)
    {
        super(digest.getAlgorithmName());

        this.digest = digest;
    }

    public void engineReset() 
    {
        digest.reset();
    }

    public void engineUpdate(
        byte    input) 
    {
        digest.update(input);
    }

    public void engineUpdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        digest.update(input, offset, len);
    }

    public byte[] engineDigest() 
    {
        byte[]  digestBytes = new byte[digest.getDigestSize()];

        digest.doFinal(digestBytes, 0);

        return digestBytes;
    }

    /**
     * classes that extend directly off us.
     */
    static public class SHA1
        extends JDKMessageDigest
        implements Cloneable
    {
        public SHA1()
        {
            super(new SHA1Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            SHA1 d = (SHA1)super.clone();
            d.digest = new SHA1Digest((SHA1Digest)digest);

            return d;
        }
    }

    static public class SHA256
        extends JDKMessageDigest
        implements Cloneable
    {
        public SHA256()
        {
            super(new SHA256Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            SHA256 d = (SHA256)super.clone();
            d.digest = new SHA256Digest((SHA256Digest)digest);

            return d;
        }
    }

    static public class SHA384
        extends JDKMessageDigest
        implements Cloneable
    {
        public SHA384()
        {
            super(new SHA384Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            SHA384 d = (SHA384)super.clone();
            d.digest = new SHA384Digest((SHA384Digest)digest);

            return d;
        }
    }

    static public class SHA512
        extends JDKMessageDigest
        implements Cloneable
    {
        public SHA512()
        {
            super(new SHA512Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            SHA512 d = (SHA512)super.clone();
            d.digest = new SHA512Digest((SHA512Digest)digest);

            return d;
        }
    }

    static public class MD2
        extends JDKMessageDigest
        implements Cloneable
    {
        public MD2()
        {
            super(new MD2Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            MD2 d = (MD2)super.clone();
            d.digest = new MD2Digest((MD2Digest)digest);

            return d;
        }
    }

    static public class MD4
        extends JDKMessageDigest
        implements Cloneable
    {
        public MD4()
        {
            super(new MD4Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            MD4 d = (MD4)super.clone();
            d.digest = new MD4Digest((MD4Digest)digest);

            return d;
        }
    }

    static public class MD5
        extends JDKMessageDigest
        implements Cloneable
    {
        public MD5()
        {
            super(new MD5Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            MD5 d = (MD5)super.clone();
            d.digest = new MD5Digest((MD5Digest)digest);

            return d;
        }
    }


}
