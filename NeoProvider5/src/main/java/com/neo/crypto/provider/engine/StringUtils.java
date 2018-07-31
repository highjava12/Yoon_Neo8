package com.neo.crypto.provider.engine;

import java.io.ByteArrayOutputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.Vector;

public final class StringUtils {

	public static String fromUTF8ByteArray(byte[] bytes) {
		int i = 0;
		int length = 0;

		while (i < bytes.length) {
			length++;
			if ((bytes[i] & 0xf0) == 0xf0) {
				// surrogate pair
				length++;
				i += 4;
			} else if ((bytes[i] & 0xe0) == 0xe0) {
				i += 3;
			} else if ((bytes[i] & 0xc0) == 0xc0) {
				i += 2;
			} else {
				i += 1;
			}
		}

		char[] cs = new char[length];

		i = 0;
		length = 0;

		while (i < bytes.length) {
			char ch;

			if ((bytes[i] & 0xf0) == 0xf0) {
				int codePoint = ((bytes[i] & 0x03) << 18) | ((bytes[i+1] & 0x3F) << 12) | ((bytes[i+2] & 0x3F) << 6) | (bytes[i+3] & 0x3F);
				int U = codePoint - 0x10000;
				char W1 = (char)(0xD800 | (U >> 10));
				char W2 = (char)(0xDC00 | (U & 0x3FF));
				cs[length++] = W1;
				ch = W2;
				i += 4;
			} else if ((bytes[i] & 0xe0) == 0xe0) {
				ch = (char)(((bytes[i] & 0x0f) << 12)
						| ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f));
				i += 3;
			} else if ((bytes[i] & 0xd0) == 0xd0) {
				ch = (char)(((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
				i += 2;
			} else if ((bytes[i] & 0xc0) == 0xc0) {
				ch = (char)(((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
				i += 2;
			} else {
				ch = (char)(bytes[i] & 0xff);
				i += 1;
			}

			cs[length++] = ch;
		}

		return new String(cs);
	}

	public static byte[] toUTF8ByteArray(String string) {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		char[] c = string.toCharArray();
		int i = 0;

		while (i < c.length) {
			char ch = c[i];

			if (ch < 0x0080) {
				bOut.write(ch);
			} else if (ch < 0x0800) {
				bOut.write(0xc0 | (ch >> 6));
				bOut.write(0x80 | (ch & 0x3f));
			} else if (ch >= 0xD800 && ch <= 0xDFFF) { // surrogate pair
				// in error - can only happen, if the Java String class has a
				// bug.
				if (i + 1 >= c.length) {
					throw new IllegalStateException("invalid UTF-16 codepoint");
				}
				char W1 = ch;
				ch = c[++i];
				char W2 = ch;
				// in error - can only happen, if the Java String class has a
				// bug.
				if (W1 > 0xDBFF) {
					throw new IllegalStateException("invalid UTF-16 codepoint");
				}
				int codePoint = (((W1 & 0x03FF) << 10) | (W2 & 0x03FF)) + 0x10000;
				bOut.write(0xf0 | (codePoint >> 18));
				bOut.write(0x80 | ((codePoint >> 12) & 0x3F));
				bOut.write(0x80 | ((codePoint >> 6) & 0x3F));
				bOut.write(0x80 | (codePoint & 0x3F));
			} else {
				bOut.write(0xe0 | (ch >> 12));
				bOut.write(0x80 | ((ch >> 6) & 0x3F));
				bOut.write(0x80 | (ch & 0x3F));
			}

			i++;
		}

		return bOut.toByteArray();
	}



	public static String toUTF8(String input) {
		try {
			return new String(toUTF8ByteArray(input),"UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
			return input;
		}
	}

	public static boolean isNull(String str) {
		if (str == null || str.equals("")) {
			return false;
		}

		return true;
	}

	public static boolean equalsIgnoreCase(String s1, String s2) {
		if ((s1 == null) || (s2 == null)) {
			return false;
		}

		return (s1.length() == s2.length()) && (s1.toUpperCase().equals(s2.toUpperCase()));
	}

	public static String d00(int i) {
		if ((i > 9) || (i < 0)) {
			return String.valueOf(i);
		} else {
			return "0" + String.valueOf(i);
		}
	}

	public static StringBuffer appendD00(StringBuffer sb, int i) {
		if ((i > 9) || (i < 0)) {
			sb.append(String.valueOf(i));
		} else {
			sb.append('0').append(String.valueOf(i));
		}

		return sb;
	}

	public static String d000(int i) {
		if ((i > 99) || (i < 0)) {
			return String.valueOf(i);
		} else if (i > 9) {
			return "0" + String.valueOf(i);
		} else {
			return "00" + String.valueOf(i);
		}
	}

	public static StringBuffer appendD000(StringBuffer sb, int i) {
		if ((i > 99) || (i < 0)) {
			sb.append(String.valueOf(i));
		} else if (i > 9) {
			sb.append("0").append(String.valueOf(i));
		} else {
			sb.append("0").append("0").append(String.valueOf(i));
		}

		return sb;
	}

	public static String d0000(int i) {
		if ((i > 999) || (i < 0)) {
			return String.valueOf(i);
		} else if (i > 99) {
			return "00" + String.valueOf(i);
		} else if (i > 9) {
			return "00" + String.valueOf(i);
		} else {
			return "000" + String.valueOf(i);
		}
	}

	public static String formatLong(long l) {
		if (l < 1000) {
			return Long.toString(l);
		}

		long l1K = (l / 1000);
		if (l1K < 1000) {
			return Long.toString(l1K) + "," + StringUtils.d000((int) (l - 1000L * l1K));
		} else {
			long l1M = (l1K / 1000);
			return Long.toString(l1M) + "," + StringUtils.d000((int) (l1K - 1000L * l1M)) + ","
			+ StringUtils.d000((int) (l - 1000L * l1K));
		}
	}

	public static String toHex00String(int c) {
		String s = Integer.toHexString(c);

		if (s.length() == 1) {
			return "0" + s;
		} else {
			return s;
		}
	}

	public static String padRight(String str, int length, char c) {
		int l = str.length();
		if (l >= length) {
			return str;
		}

		StringBuffer sb = new StringBuffer();
		sb.append(str);

		for (int i = l; i < length; i++) {
			sb.append(c);
		}

		return sb.toString();
	}

	public static char printable(char c) {
		if (c < ' ') {
			return ' ';
		} else {
			return c;
		}
	}

	public static String toBinaryText(StringBuffer buf) {
		boolean bufHasBinary = false;

		int len = buf.length();
		for (int i = 0; i < len; i++) {
			if (buf.charAt(i) < ' ') {
				bufHasBinary = true;
				break;
			}
		}

		if (bufHasBinary) {
			StringBuffer formatedDataBuf = new StringBuffer();
			for (int k = 0; k < len; k++) {
				formatedDataBuf.append(printable(buf.charAt(k)));
			}
			formatedDataBuf.append(" 0x[");
			for (int k = 0; k < len; k++) {
				formatedDataBuf.append(toHex00String(buf.charAt(k))).append(' ');
			}
			formatedDataBuf.append("]");
			buf = formatedDataBuf;
		}

		return buf.toString();
	}


	/**
	 * null인지 체크하여 null이면 ""을 return
	 * @param str
	 * @return
	 */
	public static String nullToString(String str) {
		if (str == null) {
			return "";
		} else {
			return str;
		}
	}

	/**
	 * 특정 스트링내의 일정한 pattern subString을 replace 문자열로 대치한다.
	 *
	 * 사용예) replace("2002-02-10", "-", "/")
	 * 결과)  "2002/02/10"
	 */
	public static String replace(String str, String pattern, String replace) {
		int s = 0, e = 0;

		if (str == null || str.equals("")) {
			return "";
		}

		StringBuffer result = new StringBuffer();

		while ((e = str.indexOf(pattern, s)) >= 0) {
			result.append(str.substring(s, e));
			result.append(replace);
			s = e + pattern.length();
		}

		result.append(str.substring(s));
		return result.toString();
	}

	public static String[] split(String input, char delimiter) {
		Vector           v = new Vector();
		boolean moreTokens = true;
		String subString;

		while (moreTokens) {
			int tokenLocation = input.indexOf(delimiter);
			if (tokenLocation > 0) {
				subString = input.substring(0, tokenLocation);
				v.addElement(subString);
				input = input.substring(tokenLocation + 1);
			} else {
				moreTokens = false;
				v.addElement(input);
			}
		}

		String[] res = new String[v.size()];

		for (int i = 0; i != res.length; i++) {
			res[i] = (String)v.elementAt(i);
		}
		return res;
	}

	/**
	 * 대상문자열(strTarget)에서 구분문자열(strDelimiter)을 기준으로 문자열을 분리하여
	 * 각 분리된 문자열을 배열에 할당하여 반환한다.
	 * (제한조건) 마지막 필드에도 구분시킬 문자열이 있어야 한다.
	 *
	 * @param strTarget 분리 대상 문자열
	 * @param strDelimiter 구분문자열로서 결과 문자열에는 포함되지 않는다.
	 * @return 분리된 문자열을 순서대로 배열에 격납하여 반환한다.
	 * @exception Exception
	 */
	public static String[] split(String strTarget
			, String strDelimiter) throws Exception {
		//전체 String을 Search하여 필드의 count를 얻는다.
		int cnt = 0;    // 배열의 cnt
		int pos = -1;   // delimiter를 저장하는 변수
		String tmp = strTarget;

		while ((pos = tmp.indexOf(strDelimiter)) >= 0) {
			cnt++;
			tmp = tmp.substring(pos+(strDelimiter.length()));
		}

		//반환할 배열을 생성한다.
		String[] resultStr = new String[cnt];

		//strDelimiter 의해서 구분된 값을 배열에 저장한다.
		tmp = strTarget;
		int i = 0;
		while ((pos = tmp.indexOf(strDelimiter)) >= 0) {
			if (pos == 0) {
				resultStr[i] = null;
			} else {
				resultStr[i] = tmp.substring(0,pos);
			}

			tmp = tmp.substring(pos+(strDelimiter.length()));
			i++;
		}

		return resultStr;
	}

	/**
	 * 대상문자열(strTarget)에서 필드구분자(strFieldDelimiter)와 레코드구분자(strRowDelimiter)을 기준으로 문자열을 분리하여
	 * 각 분리된 문자열을 배열에 할당하여 반환한다.
	 * (제한조건) 각 필드는 필드구분자(strFieldDelimiter)로 구분된다.
	 *          마지막 필드에도 필드구분자(strFieldDelimiter)가 있어야 한다.
	 *          각 레코드는 레코드구분자(strRowDemimiter)로 구분된다.
	 *          마지막 레코드에도 레코드구분자(strRowDemimiter)가 있어야 한다.
	 *          하나의 필드를 가지는 한 건의 레코드도 필드구분자(strFieldDelimiter), 레코드구분자(strRowDemimiter)로 종결되어야 한다.
	 *
	 * @param strTarget 분리 대상 문자열
	 * @param strFieldDelimiter 필드구분자로서 결과 문자열에는 포함되지 않는다.
	 * @param strRowDelimiter 레코드구분자로서 결과 문자열에는 포함되지 않는다.
	 * @return 분리된 문자열을 순서대로 배열에 격납하여 반환한다.
	 * @exception Exception
	 */
	public static String[][] split(String strTarget
			, String strFieldDelimiter
			, String strRowDelimiter) throws Exception {
		// 전체 배열을 Search하여 배열의 count를 얻는다.
		int cnt = 0;    // 배열의 cnt
		int pos = -1;   // delimiter를 저장하는 변수
		String tmp = strTarget;

		while ((pos = tmp.indexOf(strRowDelimiter)) >= 0) {
			cnt++;
			tmp = tmp.substring(pos+(strRowDelimiter.length()));
		}

		String[][] resultStr = new String[cnt][];

		//레코드구분자 단위로 split 메쏘드를 호출하여 결과를 반환받는다.
		tmp = strTarget;
		int i = 0;
		while ((pos = tmp.indexOf(strRowDelimiter)) >= 0) {
			if (pos == 0) {
				resultStr[i] = null;
			} else {
				resultStr[i] = split(tmp.substring(0,pos), strFieldDelimiter);
			}

			tmp = tmp.substring(pos+(strRowDelimiter.length()));
			i++;
		}

		return resultStr;
	}

	/**
	 * 대상문자열(strTarget)에서 필드구분자(strFieldDelimiter)와 레코드구분자(strRowDelimiter),
	 * 항목구분자(strItemDelimiter)을 기준으로 문자열을 분리하여
	 * 각 분리된 문자열을 배열에 할당하여 반환한다.
	 * (제한조건) 각 필드는 필드구분자(strFieldDelimiter)로 구분된다.
	 *          마지막 필드에도 필드구분자(strFieldDelimiter)가 있어야 한다.
	 *          각 레코드는 레코드구분자(strRowDelimiter)로 구분된다.
	 *          마지막 레코드에도 레코드구분자(strRowDelimiter)가 있어야 한다.
	 *          하나의 필드를 가지는 한 건의 레코드도 필드구분자(strFieldDelimiter), 레코드구분자(strRowDelimiter)로 종결되어야 한다.
	 *          마지막에는 항목구분자(strItemDelimiter)를 가져야 한다.
	 *
	 * @param strTarget 분리 대상 문자열
	 * @param strFieldDelimiter 필드구분자로서 결과 문자열에는 포함되지 않는다.
	 * @param strArrayDelimiter 레코드구분자로서 결과 문자열에는 포함되지 않는다.
	 * @param strItemDelimiter Item구분자로서 결과 문자열에는 포함되지 않는다.
	 * @return 분리된 문자열을 순서대로 배열에 격납하여 반환한다.
	 * @exception Exception
	 */
	public static String[][][] split(String strTarget
			, String strFieldDelimiter
			, String strRowDelimiter
			, String strItemDelimiter) throws Exception {
		//전체 배열을 Search하여 전체 Block의 count를 얻는다.
		int cnt = 0;  // 배열의 cnt
		int pos = -1; // delimiter를 저장하는 변수
		String tmp = strTarget;

		while ((pos = tmp.indexOf(strItemDelimiter)) >= 0) {
			cnt++;
			tmp = tmp.substring(pos+(strItemDelimiter.length()));
		}

		String[][][] resultStr = new String[cnt][][];

		//Item구분자(strRowDelimiter) 단위로 split 메쏘드를 호출하여 결과를 반환받는다.
		tmp = strTarget;
		int i = 0;
		while ((pos = tmp.indexOf(strItemDelimiter)) >= 0) {
			if (pos == 0) {
				resultStr[i] = null;
			} else {
				resultStr[i] = split(tmp.substring(0,pos), strFieldDelimiter, strRowDelimiter);
			}

			tmp = tmp.substring(pos+(strRowDelimiter.length()));
			i++;
		}

		return resultStr;
	}

	/**
	 * split된 문자열을 화면에 출력
	 * @param parsedStr
	 */
	public static void printParsedString(String[][][] parsedStr) {
		for (int k = 0; k < parsedStr.length; k++) {
			for (int j = 0; j < parsedStr[k].length; j++) {
				for (int i = 0; i < parsedStr[k][j].length; i++) {
					System.out.println("배열 ["+k+"]["+j+"]["+i+"] : " + nullToString(parsedStr[k][j][i]));
				}
			}
		}
	}

	//    public static byte[] getTokenId(byte[] tokenId) {
	//    	(new Random()).nextBytes(tokenId);
	//    	return tokenId;
	//    }
	//
	//    public static String getRandomStr() {
	//    	String tokenId = "";
	//    	Random rand = new Random(System.currentTimeMillis());
	//		tokenId = DateUtils.getDateTimeSec() + tokenId + String.valueOf(Math.abs(rand.nextInt(99990)+10));
	//
	//		return tokenId;
	//	}
	//
	//    public static String getRandom() {
	//    	String tokenId = "";
	//    	Random rand = new Random();
	//		tokenId = String.valueOf(Math.abs(rand.nextInt(99990)+10));
	//
	//		return tokenId;
	//	}
	//
	//    public static int getInt() {
	//		int ranNum = 0;
	//		Random rand = new Random(System.currentTimeMillis());
	//		ranNum = Math.abs(rand.nextInt(990)+10);
	//
	//		return ranNum;
	//	}

	/**
	 * A locale independent version of toUpperCase.
	 * 
	 * @param string input to be converted
	 * @return a US Ascii uppercase version
	 */
	public static String toUpperCase(String string) {
		boolean changed = false;
		char[] chars = string.toCharArray();

		for (int i = 0; i != chars.length; i++) {
			char ch = chars[i];
			if ('a' <= ch && 'z' >= ch) {
				changed = true;
				chars[i] = (char)(ch - 'a' + 'A');
			}
		}

		if (changed) {
			return new String(chars);
		}

		return string;
	}

	/**
	 * A locale independent version of toLowerCase.
	 * 
	 * @param string input to be converted
	 * @return a US ASCII lowercase version
	 */
	public static String toLowerCase(String string) {
		boolean changed = false;
		char[] chars = string.toCharArray();

		for (int i = 0; i != chars.length; i++) {
			char ch = chars[i];
			if ('A' <= ch && 'Z' >= ch) {
				changed = true;
				chars[i] = (char)(ch - 'A' + 'a');
			}
		}

		if (changed) {
			return new String(chars);
		}

		return string;
	}

	public static byte[] toByteArray(String string) {
		byte[] bytes = new byte[string.length()];

		for (int i = 0; i != bytes.length; i++) {
			char ch = string.charAt(i);

			bytes[i] = (byte)ch;
		}

		return bytes;
	}

	public static byte[] str2bin(String byt) {
		if (byt == null) {
			return null;
		}
		byte[] temp = new byte[byt.length() / 2];
		int itemp = 0;
		for (int i = 0; i < byt.length(); i += 2) {
			String sByte = byt.substring(i, i + 2);
			int n = (char)Integer.parseInt(sByte, 16);
			temp[i - itemp] = (byte)n;
			itemp++;
		}
		return temp;
	}

	public static String bin2str(byte[] byt) {
		if (byt == null) {
			return "";
		}
		StringBuffer buffer = new StringBuffer(byt.length);
		int i;
		byte by;
		int itemp1, itemp2;

		for (i = 0; i < byt.length; i++) {
			itemp1 = itemp2 = 0;
			by = 0x00;
			Byte bt;
			bt = new Byte(byt[i]);
			int itemp = bt.intValue();
			itemp = itemp & 0x000000ff;
			itemp1 = itemp >>> 4;
		Integer in1 = new Integer(itemp1);
		by = in1.byteValue();
		buffer.append(getHexChar(by));
		by = 0x00;
		itemp2 = itemp & 0x0000000f;
		Integer in2 = new Integer(itemp2);
		by = in2.byteValue();
		buffer.append(getHexChar(by));
		}
		return buffer.toString();
	}

	public static String bin2printstr(byte[] byt) {
		if (byt == null) {
			return "";
		}
		StringBuffer buffer = new StringBuffer(byt.length);
		int i;
		byte by;
		int itemp1, itemp2;

		for (i = 0; i < byt.length; i++) {
			itemp1 = itemp2 = 0;
			by = 0x00;
			Byte bt;
			bt = new Byte(byt[i]);
			int itemp = bt.intValue();
			itemp = itemp & 0x000000ff;
			itemp1 = itemp >>> 4;
			Integer in1 = new Integer(itemp1);
			by = in1.byteValue();
			buffer.append(getHexChar(by));
			by = 0x00;
			itemp2 = itemp & 0x0000000f;
			Integer in2 = new Integer(itemp2);
			by = in2.byteValue();
			buffer.append(getHexChar(by));
			if (i + 1 < byt.length) {
				buffer.append(" ");
			}
		}
		return buffer.toString();
	}

	public static char getHexChar(byte b) {
		switch (b) {
		case 0x00:
			return '0';
		case 0x01:
			return '1';
		case 0x02:
			return '2';
		case 0x03:
			return '3';
		case 0x04:
			return '4';
		case 0x05:
			return '5';
		case 0x06:
			return '6';
		case 0x07:
			return '7';
		case 0x08:
			return '8';
		case 0x09:
			return '9';
		case 0x0a:
			return 'A';
		case 0x0b:
			return 'B';
		case 0x0c:
			return 'C';
		case 0x0d:
			return 'D';
		case 0x0e:
			return 'E';
		case 0x0f:
			return 'F';
		}

		return 'X';
	}

	//    public static String checkNull(String checkString) {
	//    	if (checkString == null) checkString = "";
	//    	return checkString;
	//    }

	public static String millisecondToTime(String milisecond) {
		if (milisecond != null) {
			StringBuffer timeString = new StringBuffer();
			try {
				TimeZone timeZone = TimeZone.getTimeZone("GMT+09:00");
				Calendar cal = Calendar.getInstance(timeZone, Locale.KOREA);
				cal.setTime(new Date(Long.parseLong( milisecond )));

				timeString.append(cal.get(Calendar.YEAR)+"년 ");
				timeString.append((cal.get(Calendar.MONTH)+1)+"월 ");
				timeString.append(cal.get(Calendar.DATE)+"일 ");
				timeString.append(cal.get(Calendar.HOUR)+"시 ");
				timeString.append(cal.get(Calendar.MINUTE)+"분 ");
				timeString.append(cal.get(Calendar.SECOND)+"초");
			} catch (NumberFormatException e) {
				//e.printStackTrace();
				return "";
			}
			return timeString.toString();
		} else {
			return "";
		}
	}

	/**
	 * XML String 으로부터 속성이 attributeName인 값을 반환한다.
	 * 
	 * <pre>
	 *     getStringAttribute("<Attribute name="agentId"></Attribute>", "name");
	 *     하면 결과는, agentId 이 된다.
	 * </pre>
	 * @param xml
	 * @param attributeName
	 * @return
	 */
	public static String getStringAttribute(String xml, String attributeName) {
		String sTagName = attributeName + "=\"";
		String eTagName = "\"";

		int start = xml.indexOf(sTagName);
		if (start == -1) {
			return null;
		}
		int offset = sTagName.length();
		int end = xml.indexOf(eTagName, start + offset);

		return xml.substring(start + offset, end);
	}

	/**
	 * XML String 으로부터 태그가 tagName인 값을 반환한다.
	 * 
	 * <pre>
	 *     getContent("<SessionId>03428909a30ff1e31168327f79474984</SessionId>", "SessionId");
	 *     하면 결과는, 03428909a30ff1e31168327f79474984 이 된다.
	 * </pre>
	 * 
	 * @param xml
	 * @param tagName
	 * @return
	 */
	public static String getContent(String xml, String tagName) {
		String sTagName = "<" + tagName;
		String eTagName = "</" + tagName + ">";

		if (xml.indexOf(sTagName) == -1) {
			return null;
		}
		int start = xml.indexOf(">", xml.indexOf(sTagName));
		if (start == -1) {
			return null;
		}
		int end = xml.indexOf(eTagName);

		return xml.substring(start + 1, end);
	}

	/**
	 * XML String 으로부터 태그가 tagName을 포함한 값을 반환한다.
	 * 
	 * <pre>
	 *     <SessionValues>
	 *         <Attribute name="agentId">
	 *             <AttributeValue type="String">NEIS01A1</AttributeValue>
	 *         </Attribute>
	 *         <Attribute name="tokenId">
	 *             <AttributeValue type="Integer">1234</AttributeValue>
	 *         </Attribute>
	 *     </SessionValues>
	 * 
	 *      XML이 위와 같을 때, getElement(xml, "Attribute"); 하면, 그 결과는 다음과 같다.
	 *         <Attribute name="agentId">
	 *             <AttributeValue type="String">NEIS01A1</AttributeValue>
	 *         </Attribute>
	 *         <Attribute name="tokenId">
	 *             <AttributeValue type="Integer">1234</AttributeValue>
	 *         </Attribute>
	 * </pre>
	 * 
	 * @param xml
	 * @param tagName
	 * @return
	 */
	public static String getElement(String xml, String tagName) {
		String sTagName = "<" + tagName;
		String eTagName = "</" + tagName + ">";

		if (xml.indexOf(sTagName) == -1) {
			return null;
		}
		int start = xml.indexOf(sTagName);
		if (start == -1) {
			return null;
		}
		int end = xml.indexOf(eTagName) + eTagName.length();

		return xml.substring(start, end);
	}


	public static String delCRLF( String data )
	{
		StringBuffer sb = new StringBuffer();
		StringTokenizer st = new StringTokenizer( data, "\r\n" );
		while(st.hasMoreTokens()) {
			sb.append( st.nextToken() );
		}

		return sb.toString();
	}

	public static String substring( String data, String header, String footer )
	{
		return (new StringBuffer( data )).substring( header.length(), data.length()-footer.length() );
	}
	
	

}
