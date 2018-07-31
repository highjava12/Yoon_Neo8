package com.neo.security.asn1;

import java.io.IOException;
import java.io.InputStream;


class DefiniteLengthInputStream
        extends LimitedInputStream
{
    private int               _length;

    DefiniteLengthInputStream(
        InputStream in,
        int         length)
    {
        super(in);

        _length = length;
    }

    
	public int read()
        throws IOException
    {
        if (_length-- > 0)
        {
            return _in.read();
        }
        else
        {
            setParentEofDetect(true);

            return -1;
        }
    }
}
