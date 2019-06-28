 

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Random;

/**
 * <pre>
 *     author: Blankj
 *     blog  : http://blankj.com
 *     time  : 2016/8/16
 *     desc  : 字符串相关工具类
 * </pre>
 */
public class StringUtils {

    private StringUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    /**
     * 判断字符串是否为null或长度为0
     *
     * @param s 待校验字符串
     * @return {@code true}: 空<br> {@code false}: 不为空
     */
    public static boolean isEmpty(CharSequence s) {
        return s == null || s.length() == 0;
    }

    /**
     * 判断字符串是否为null或全为空格
     *
     * @param s 待校验字符串
     * @return {@code true}: null或全空格<br> {@code false}: 不为null且不全空格
     */
    public static boolean isSpace(String s) {
        return (s == null || s.trim().length() == 0);
    }

    /**
     * 判断两字符串是否相等
     *
     * @param a 待校验字符串a
     * @param b 待校验字符串b
     * @return {@code true}: 相等<br>{@code false}: 不相等
     */
    public static boolean equals(CharSequence a, CharSequence b) {
        if (a == b) return true;
        int length;
        if (a != null && b != null && (length = a.length()) == b.length()) {
            if (a instanceof String && b instanceof String) {
                return a.equals(b);
            } else {
                for (int i = 0; i < length; i++) {
                    if (a.charAt(i) != b.charAt(i)) return false;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * 判断两字符串忽略大小写是否相等
     *
     * @param a 待校验字符串a
     * @param b 待校验字符串b
     * @return {@code true}: 相等<br>{@code false}: 不相等
     */
    public static boolean equalsIgnoreCase(String a, String b) {
        return (a == b) || (b != null) && (a.length() == b.length()) && a.regionMatches(true, 0, b, 0, b.length());
    }

    /**
     * null转为长度为0的字符串
     *
     * @param s 待转字符串
     * @return s为null转为长度为0字符串，否则不改变
     */
    public static String null2Length0(String s) {
        return s == null ? "" : s;
    }

    /**
     * 返回字符串长度
     *
     * @param s 字符串
     * @return null返回0，其他返回自身长度
     */
    public static int length(CharSequence s) {
        return s == null ? 0 : s.length();
    }

    /**
     * 首字母大写
     *
     * @param s 待转字符串
     * @return 首字母大写字符串
     */
    public static String upperFirstLetter(String s) {
        if (isEmpty(s) || !Character.isLowerCase(s.charAt(0))) return s;
        return String.valueOf((char) (s.charAt(0) - 32)) + s.substring(1);
    }

    /**
     * 首字母小写
     *
     * @param s 待转字符串
     * @return 首字母小写字符串
     */
    public static String lowerFirstLetter(String s) {
        if (isEmpty(s) || !Character.isUpperCase(s.charAt(0))) return s;
        return String.valueOf((char) (s.charAt(0) + 32)) + s.substring(1);
    }

    /**
     * 反转字符串
     *
     * @param s 待反转字符串
     * @return 反转字符串
     */
    public static String reverse(String s) {
        int len = length(s);
        if (len <= 1) return s;
        int mid = len >> 1;
        char[] chars = s.toCharArray();
        char c;
        for (int i = 0; i < mid; ++i) {
            c = chars[i];
            chars[i] = chars[len - i - 1];
            chars[len - i - 1] = c;
        }
        return new String(chars);
    }

    /**
     * 转化为半角字符
     *
     * @param s 待转字符串
     * @return 半角字符串
     */
    public static String toDBC(String s) {
        if (isEmpty(s)) return s;
        char[] chars = s.toCharArray();
        for (int i = 0, len = chars.length; i < len; i++) {
            if (chars[i] == 12288) {
                chars[i] = ' ';
            } else if (65281 <= chars[i] && chars[i] <= 65374) {
                chars[i] = (char) (chars[i] - 65248);
            } else {
                chars[i] = chars[i];
            }
        }
        return new String(chars);
    }

    /**
     * 转化为全角字符
     *
     * @param s 待转字符串
     * @return 全角字符串
     */
    public static String toSBC(String s) {
        if (isEmpty(s)) return s;
        char[] chars = s.toCharArray();
        for (int i = 0, len = chars.length; i < len; i++) {
            if (chars[i] == ' ') {
                chars[i] = (char) 12288;
            } else if (33 <= chars[i] && chars[i] <= 126) {
                chars[i] = (char) (chars[i] + 65248);
            } else {
                chars[i] = chars[i];
            }
        }
        return new String(chars);
    }
    private static String randomString="";

    public static String getRandomString(int length){
        if(randomString.isEmpty())
        {
            //定义一个字符串（A-Z，a-z，0-9）即62位；
            String str="zxcvbnmlkjhgfdsaqwertyuiopQWERTYUIOPASDFGHJKLZXCVBNM1234567890";
            //由Random生成随机数
            Random random=new Random();
            StringBuffer sb=new StringBuffer();
            //长度为几就循环几次
            for(int i=0; i<length; ++i){
                //产生0-61的数字
                int number=random.nextInt(62);
                //将产生的数字通过length次承载到sb中
                sb.append(str.charAt(number));
            }
            //将承载的字符转换成字符串
            randomString = sb.toString();
        }

        return randomString;
    }
    /**
     * 将字节数组转化为十六进制字符串表示
     *
     * @param bytes
     * @return
     */
    public static final String bytes2Hex(byte[] bytes) {
        StringBuffer sb = new StringBuffer(bytes.length * 2);

        for (int i = 0; i < bytes.length; i++) {
            sb.append(bcdLookup[(bytes[i] >>> 4) & 0x0f]);
            sb.append(bcdLookup[bytes[i] & 0x0f]);
        }

        return sb.toString();
    }

    /**
     * 将十六进制字符串转化为字节数组表示
     *
     * @param s
     * @return
     */
    public static final byte[] hex2Bytes(String s) {
        byte[] bytes = new byte[s.length() / 2];

        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }

        return bytes;
    }

    public static final char[] bcdLookup = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
            'f' };

    public static String encodeBASE64(String source, String charsetName) throws UnsupportedEncodingException {
        byte[] bytes = charsetName == null ? source.getBytes() : source.getBytes(charsetName);
        return encodeBASE64(bytes, charsetName);
    }

    /**
     * 把字节数组转换为base64编码
     *
     * @param bytes       字节数组
     * @param charsetName 字符集名称
     * @return 转换后的字符串
     * @throws UnsupportedEncodingException
     */
    public static String encodeBASE64(byte[] bytes, String charsetName) throws UnsupportedEncodingException {

        byte[] data = Base64.getEncoder().encode(bytes);
        String s = charsetName == null ? new String(data) : new String(data, charsetName);

        return s;
    }

    public static String decBASE64(String content, String charsetName) throws UnsupportedEncodingException {
        byte[] bytes = decodeBASE64(content, charsetName);

        return charsetName == null ? new String(bytes) : new String(bytes, charsetName);
    }

    /**
     * 将base64编码的字符串转为字节数组
     *
     * @param text        字符串
     * @param charsetName 字符集名称
     * @return 字节数组
     * @throws UnsupportedEncodingException
     */
    public static byte[] decodeBASE64(String content, String charsetName) throws UnsupportedEncodingException {
        // BASE64Decoder b64 = new BASE64Decoder();
        // return b64.decodeBuffer(text);

        byte[] bytes = charsetName == null ? content.getBytes() : content.getBytes(charsetName);

        return Base64.getDecoder().decode(bytes);
    }

    /**
     * 拷贝字节数组
     *
     * @param des    目标字节数组
     * @param desPos 目标字节数组起始索引
     * @param src    源字节数组
     * @param srcPos 源字节数组起始索引
     * @param len    拷贝长度
     */
    public static void copyBuf(byte[] des, int desPos, byte[] src, int srcPos, int len) {
        for (int i = 0; i < len; i++) {
            des[desPos + i] = src[srcPos + i];
        }
    }

    /**
     * 字节数组相加
     *
     * @param a
     * @param b
     * @return
     */
    public static byte[] appendBuf(byte[] a, byte[] b) {
        int lenA = a.length;
        int lenB = b.length;

        byte[] c = new byte[a.length + b.length];
        copyBuf(c, 0, a, 0, lenA);
        copyBuf(c, lenA, b, 0, lenB);

        return c;
    }

    /**
     * 左补空格或零
     *
     * @param strSrc       需要格式化的字符串
     * @param strSrcLength 目标长度
     * @param flag         填充的字符,默认用0填充
     * @return
     */
    public static String stringLeftPading(String strSrc, int strSrcLength, char flag, boolean fix) {
        String strReturn = "";
        String strtemp = "";
        int curLength = strSrc.trim().length();
        if (strSrc != null && curLength > strSrcLength) {
            if (fix)
                strReturn = strSrc.trim().substring(0, strSrcLength);
            else
                strReturn = strSrc;
        } else if (strSrc != null && curLength == strSrcLength) {
            strReturn = strSrc.trim();
        } else {
            for (int i = 0; i < (strSrcLength - curLength); i++) {
                strtemp = strtemp + flag;
            }
            strReturn = strtemp + strSrc.trim();
        }
        return strReturn;
    }
}