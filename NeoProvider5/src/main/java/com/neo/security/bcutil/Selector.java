package com.neo.security.bcutil;

public interface Selector<T>
    extends Cloneable
{
    boolean match(T obj);

    Object clone();
}
