package com.neo.security.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ProviderUtil
{
    private static final long  MAX_MEMORY = Runtime.getRuntime().maxMemory();

    static int getReadLimit(InputStream in)
        throws IOException
    {
        if (in instanceof ByteArrayInputStream)
        {
            return in.available();
        }

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }
}
