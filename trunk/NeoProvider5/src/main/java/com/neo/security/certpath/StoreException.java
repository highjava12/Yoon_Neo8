package com.neo.security.certpath;

public class StoreException
    extends RuntimeException
{
    private Throwable _e;

    public StoreException(String s)
    {
    	super(s);
    }
    
    public StoreException(String s, Throwable e)
    {
        super(s);
        _e = e;
        this.initCause(e);
    }

    public Throwable getCause()
    {
        return _e;
    }
}
