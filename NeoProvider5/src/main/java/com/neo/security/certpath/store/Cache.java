package com.neo.security.certpath.store;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public abstract class Cache {
    
    protected Cache() {
    	// empty
    }
    
    /**
     * Return the number of currently valid entries in the cache.
     */
    public abstract int size();
    
    /**
     * Remove all entries from the cache.
     */
    public abstract void clear();
    
    /**
     * Add an entry to the cache.
     */
    public abstract void put(Object key, Object value);

    /**
     * Get a value from the cache.
     */
    public abstract Object get(Object key);

    /**
     * Remove an entry from the cache.
     */
    public abstract void remove(Object key);
    
    /**
     * Return a new memory cache with the specified maximum size, unlimited
     * lifetime for entries, with the values held by SoftReferences.
     */
    public static Cache newSoftMemoryCache(int size) {
    	return new MemoryCache(true, size);
    }

    /**
     * Return a new memory cache with the specified maximum size, the
     * specified maximum lifetime (in seconds), with the values held 
     * by SoftReferences.
     */
    public static Cache newSoftMemoryCache(int size, int timeout) {
    	return new MemoryCache(true, size, timeout);
    }

    /**
     * Return a new memory cache with the specified maximum size, unlimited
     * lifetime for entries, with the values held by standard references.
     */
    public static Cache newHardMemoryCache(int size) {
    	return new MemoryCache(false, size);
    }
    
    /**
     * Return a dummy cache that does nothing.
     */
    public static Cache newNullCache() {
    	return NullCache.INSTANCE;
    }

    /**
     * Return a new memory cache with the specified maximum size, the
     * specified maximum lifetime (in seconds), with the values held 
     * by standard references.
     */
    public static Cache newHardMemoryCache(int size, int timeout) {
    	return new MemoryCache(false, size, timeout);
    }

    /**
     * Utility class that wraps a byte array and implements the equals()
     * and hashCode() contract in a way suitable for Maps and caches.
     */
    public static class EqualByteArray {
	
	private final byte[] b;
	private volatile int hash;
	
	public EqualByteArray(byte[] b) {
	    this.b = b;
	}
	
	public int hashCode() {
	    int h = hash;
	    if (h == 0) {
		h = b.length + 1;
		for (int i = 0; i < b.length; i++) {
		    h += (b[i] & 0xff) * 37;
		}
		hash = h;
	    }
	    return h;
	}
	
	public boolean equals(Object obj) {
	    if (this == obj) {
		return true;
	    }
	    if (obj instanceof EqualByteArray == false) {
		return false;
	    }
	    EqualByteArray other = (EqualByteArray)obj;
	    return Arrays.equals(this.b, other.b);
	}
    }
	
}

class NullCache extends Cache {
    
    final static Cache INSTANCE = new NullCache();
    
    private NullCache() {
    	// empty
    }

    public int size() {
    	return 0;
    }
    
    public void clear() {
    	// empty
    }
    
    public void put(Object key, Object value) {
    	// empty
    }

    public Object get(Object key) {
    	return null;
    }

    public void remove(Object key) {
    	// empty
    }
    
}

class MemoryCache extends Cache {
    
    private final static float LOAD_FACTOR = 0.75f;
    
    // XXXX
    private final static boolean DEBUG = false;
    
    private final Map cacheMap;
    private final int maxSize;
    private final int lifetime;
    private final ReferenceQueue queue;
    
    public MemoryCache(boolean soft, int maxSize) {
	this(soft, maxSize, 0);
    }
    
    public MemoryCache(boolean soft, int maxSize, int lifetime) {
		this.maxSize = maxSize;
		this.lifetime = lifetime * 1000;
		this.queue = soft ? new ReferenceQueue() : null;
		int buckets = (int)(maxSize / LOAD_FACTOR) + 1;
		cacheMap = new LinkedHashMap(buckets, LOAD_FACTOR, true);
    }
    
    /**
     * Empty the reference queue and remove all corresponding entries
     * from the cache.
     *
     * This method should be called at the beginning of each public
     * method.
     */
    private void emptyQueue() {
		if (queue == null) {
		    return;
		}
		int startSize = cacheMap.size();
		while (true) {
		    CacheEntry entry = (CacheEntry)queue.poll();
		    if (entry == null) {
		    	break;
		    }
		    Object key = entry.getKey();
		    if (key == null) {
				// key is null, entry has already been removed
				continue;
		    }
		    CacheEntry currentEntry = (CacheEntry) cacheMap.remove(key);
		    // check if the entry in the map corresponds to the expired
		    // entry. If not, readd the entry
		    if ((currentEntry != null) && (entry != currentEntry)) {
		    	cacheMap.put(key, currentEntry);
		    }
		}
		if (DEBUG) {
		    int endSize = cacheMap.size();
		    if (startSize != endSize) {
		    	System.out.println("*** Expunged " + (startSize - endSize) + " entries, " + endSize + " entries left");
		    }
		}
    }
    
    /**
     * Scan all entries and remove all expired ones.
     */
    private void expungeExpiredEntries() {
		emptyQueue();
		if (lifetime == 0) {
		    return;
		}
		int cnt = 0;
		long time = System.currentTimeMillis();
		for (Iterator t = cacheMap.values().iterator();
			t.hasNext(); ) {
		    CacheEntry entry = (CacheEntry) t.next();
		    if (entry.isValid(time) == false) {
				t.remove();
				cnt++;
		    }
		}
		if (DEBUG) {
		    if (cnt != 0) {
		    	System.out.println("Removed " + cnt + " expired entries, remaining " + cacheMap.size());
		    }
		}
    }
    
    public synchronized int size() {
		expungeExpiredEntries();
		return cacheMap.size();
    }
    
    public synchronized void clear() {
		if (queue != null) {
		    // if this is a SoftReference cache, first invalidate() all
		    // entries so that GC does not have to enqueue them
		    //for (CacheEntry entry : cacheMap.values()) {
			 Iterator it = cacheMap.values().iterator();
			 while(it.hasNext()) {
				 CacheEntry entry = (CacheEntry)it.next();
				 entry.invalidate();
		    }
		    while (queue.poll() != null) {
		    	// empty
		    }
		}
		cacheMap.clear();
    }
    
    public synchronized void put(Object key, Object value) {
		emptyQueue();
		long expirationTime = (lifetime == 0) ? 0 : 
						System.currentTimeMillis() + lifetime;
		CacheEntry newEntry = newEntry(key, value, expirationTime, queue);
		CacheEntry oldEntry = (CacheEntry) cacheMap.put(key, newEntry);
		if (oldEntry != null) {
		    oldEntry.invalidate();
		    return;
		}
		if (cacheMap.size() > maxSize) {
		    expungeExpiredEntries();
		    if (cacheMap.size() > maxSize) { // still too large?
				Iterator t = cacheMap.values().iterator();
				CacheEntry lruEntry = (CacheEntry) t.next();
				if (DEBUG) {
				    System.out.println("** Overflow removal " + lruEntry.getKey() + " | " + lruEntry.getValue());
				}
				t.remove();
				lruEntry.invalidate();
		    }
		}
    }
    
    public synchronized Object get(Object key) {
		emptyQueue();
		CacheEntry entry = (CacheEntry) cacheMap.get(key);
		if (entry == null) {
		    return null;
		}
		long time = (lifetime == 0) ? 0 : System.currentTimeMillis();
		if (entry.isValid(time) == false) {
		    if (DEBUG) {
		    	System.out.println("Ignoring expired entry");
		    }
		    cacheMap.remove(key);
		    return null;
		}
		return entry.getValue();
    }
    
    public synchronized void remove(Object key) {
		emptyQueue();
		CacheEntry entry = (CacheEntry) cacheMap.remove(key);
		if (entry != null) {
		    entry.invalidate();
		}
    }
    
    protected CacheEntry newEntry(Object key, Object value, 
	    long expirationTime, ReferenceQueue queue) {
		if (queue != null) {
		    return new SoftCacheEntry(key, value, expirationTime, queue);
		} else {
		    return new HardCacheEntry(key, value, expirationTime);
		}
    }
    
    private static interface CacheEntry {
	
	boolean isValid(long currentTime);
	
	void invalidate();
	
	Object getKey();
	
	Object getValue();
	
    }
    
    private static class HardCacheEntry implements CacheEntry {
	
		private Object key, value;
		private long expirationTime;
	
		HardCacheEntry(Object key, Object value, long expirationTime) {
		    this.key = key;
		    this.value = value;
		    this.expirationTime = expirationTime;
		}
		
		public Object getKey() {
		    return key;
		}
		
		public Object getValue() {
		    return value;
		}
		
		public boolean isValid(long currentTime) {
		    boolean valid = (currentTime <= expirationTime);
		    if (valid == false) {
		    	invalidate();
		    }
		    return valid;
		}
		
		public void invalidate() {
		    key = null;
		    value = null;
		    expirationTime = -1;
		}
	    }
	    
	    private static class SoftCacheEntry
		    extends SoftReference implements CacheEntry {
		
		private Object key;
		private long expirationTime;
		
		SoftCacheEntry(Object key, Object value, long expirationTime, 
			ReferenceQueue queue) {
		    super(value, queue);
		    this.key = key;
		    this.expirationTime = expirationTime;
		}
		
		public Object getKey() {
		    return key;
		}
		
		public Object getValue() {
		    return get();
		}
		
		public boolean isValid(long currentTime) {
		    boolean valid = (currentTime <= expirationTime) && (get() != null);
		    if (valid == false) {
		    	invalidate();
		    }
		    return valid;
		}
		
		public void invalidate() {
		    clear();
		    key = null;
		    expirationTime = -1;
		}
    }
}
