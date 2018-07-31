package com.neo.security.bcutil;

import java.util.Collection;

public interface Store<T>
{
    Collection<T> getMatches(Selector<T> selector)
        throws StoreException;
}
