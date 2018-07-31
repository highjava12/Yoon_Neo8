/*
 * Copyright (c) 1996, 2006, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.neo.security.provider;

import java.security.AccessController;
import java.security.Provider;
import java.util.LinkedHashMap;
import java.util.Map;

import com.neo.crypto.provider.NeoJceEntries;
import com.neo.security.action.PutAllAction;
import com.neo.security.rsa.NeoRsaSignEntries;



/**
 * The SUN Security Provider.
 *
 */
public final class NeoProvider extends Provider {
	public static final String PROVIDER_NAME = "NEO";
	
	private static final long serialVersionUID = -2589136950907696685L;
	private static final String INFO = "NEO JCA/JCE Provider";

    public NeoProvider() {
        super(PROVIDER_NAME, 1.5, INFO);

        
        
        // if there is no security manager installed, put directly into
        // the provider. Otherwise, create a temporary map and use a
        // doPrivileged() call at the end to transfer the contents
        if (System.getSecurityManager() == null) {
            NeoEntries.putEntries(this);
            NeoJceEntries.putEntries(this);
            NeoRsaSignEntries.putEntries(this);
        } else {
            // use LinkedHashMap to preserve the order of the PRNGs
            Map<Object, Object> map = new LinkedHashMap<Object, Object>();
            NeoEntries.putEntries(map);
            NeoJceEntries.putEntries(map);
            NeoRsaSignEntries.putEntries(map);
            AccessController.doPrivileged(new PutAllAction(this, map));
        }
    }

	//this code allows to break limit if client jdk/jre has no unlimited policy files for JCE.
	//it should be run once. So this static section is always execute during the class loading process.
	//this code is useful when working with Bouncycastle library.

//	static {
//	    try {
//	        Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
//	        field.setAccessible(true);
//	        field.set(null, java.lang.Boolean.FALSE);
//	    } catch (Exception ex) {
//	    }
//	}
}
