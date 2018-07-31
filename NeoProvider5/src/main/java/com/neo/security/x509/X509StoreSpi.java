package com.neo.security.x509;

import java.util.Collection;

import com.neo.security.bcutil.Selector;

public abstract class X509StoreSpi
{
    public abstract void engineInit(X509StoreParameters parameters);

    public abstract Collection engineGetMatches(Selector selector);
}
