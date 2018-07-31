package com.neo.security.certpath.store;

import java.util.Collection;

import com.neo.security.bcutil.Selector;
import com.neo.security.certpath.util.CollectionStore;
import com.neo.security.x509.X509StoreParameters;
import com.neo.security.x509.X509StoreSpi;

public class X509StoreCRLCollection
    extends X509StoreSpi
{
    private CollectionStore _store;

    public X509StoreCRLCollection()
    {
    }

    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509CollectionStoreParameters))
        {
            throw new IllegalArgumentException(params.toString());
        }

        _store = new CollectionStore(((X509CollectionStoreParameters)params).getCollection());
    }

    public Collection engineGetMatches(Selector selector)
    {
        return _store.getMatches(selector);
    }
}
