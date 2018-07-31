package com.neo.security.certpath.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class AmFile {

	public static final String separator = File.separator;
	
	File fd;

	public AmFile(String path)
	{
		if (path == null)
			throw new IllegalArgumentException("File path is null.");

		final String pathf = path;

		fd = (File) AccessController
				.doPrivileged(new PrivilegedAction()
				{
					public Object run()
					{
						return new File(pathf);
					}
				});
	}

	
	public String getAbsolutePath()
	{
		final File fdf = fd;

		return (String) AccessController
				.doPrivileged(new PrivilegedAction()
				{
					public Object run()
					{
						return fdf.getAbsolutePath();
					}
				});
	}

	public boolean exists()
	{
		final File fdf = fd;

		return ((Boolean) AccessController
				.doPrivileged(new PrivilegedAction()
				{
					public Object run()
					{
						return new Boolean(fdf.exists());
					}
				})).booleanValue();
	}

	public boolean delete()
	{
		final File fdf = fd;

		return ((Boolean) AccessController
				.doPrivileged(new PrivilegedAction()
				{
					public Object run()
					{
						return new Boolean(fdf.delete());
					}
				})).booleanValue();
	}

	public String[] list(FilenameFilter filter)
	{
		final File fdf = fd;
		final FilenameFilter filterf = filter;

		return (String[]) AccessController
				.doPrivileged(new PrivilegedAction()
				{
					public Object run()
					{
						return fdf.list(filterf);
					}
				});
	}


	public static String[] listFiles(String path, FilenameFilter filter)
	{
		if (filter == null)
			throw new IllegalArgumentException("File filter is null.");

		final String pathf = path;
		final FilenameFilter filterf = filter;

		String[] result = (String[]) AccessController
				.doPrivileged(new PrivilegedAction()
				{
					public Object run()
					{
						return (new File(pathf)).list(filterf);
					}
				});

		return result;
	}


	public FileOutputStream getFileOutputStream() throws FileNotFoundException
	{
		final File fdf = fd;
		try
		{
			return (FileOutputStream) AccessController
					.doPrivileged(new PrivilegedExceptionAction()
					{
						public Object run() throws FileNotFoundException
						{
							return new FileOutputStream(fdf);
						}
					});
		}
		catch (PrivilegedActionException e)
		{
			throw (FileNotFoundException)e.getCause();
		}
	}

	public FileInputStream getFileInputStream() throws FileNotFoundException
	{
		final File fdf = fd;
		try
		{
			return (FileInputStream) AccessController
					.doPrivileged(new PrivilegedExceptionAction()
					{
						public Object run() throws FileNotFoundException
						{
							return new FileInputStream(fdf);
						}
					});
		}
		catch (PrivilegedActionException e)
		{
			throw (FileNotFoundException)e.getCause();
		}
	}

}
