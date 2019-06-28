package com.imi.imidatacollect.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * AES 是一种可逆加密算法，对用户的敏感信息加密处理 对原始数据进行AES加密后，在进行Base64编码转化；
 */
public class AesUtil {

	/*
	 * 加密用的Key 可以用26个字母和数字组成 此处使用AES-128-CBC加密模式，key需要为16位。
	 */
	private static String sKey = "12345678901234561234567890123456";// key，加密的key
	private static String ivParameter = "1201230125462244";// 偏移量,4*4矩阵

	/**
	 * 加密.密钥长度必须为16的整数倍
	 * 
	 * @param content 要加密的内容
	 * @param key     加密的秘钥
	 * @return 加密后的字节数组,以16进制字符串表示
	 * @throws Exception
	 */
	public static String encrypt(String content, String key) throws Exception {
		byte[] encrypted = encrypt(content.getBytes("utf-8"), key);
		return StringUtils.bytes2Hex(encrypted);
	}

	/**
	 * 加密.密钥长度必须为16的整数倍
	 * 
	 * @param content 要加密的内容
	 * @param key     加密的秘钥
	 * @return 加密后的字节数组
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] content, String key) throws Exception {
		if (key == null || key.length() % 16 != 0) {
			return null;
		}

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] raw = key.getBytes("utf8");
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes("utf8"));// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
		byte[] encrypted = cipher.doFinal(content);

		return encrypted;
	}

	/**
	 * 解密
	 * 
	 * @param content 待解密的内容,以16进制表示的字节数组
	 * @param key 解密密钥
	 * @return 解密后的字符串
	 * @throws Exception
	 */
	public static String decrypt(String content, String key) throws Exception {
		try {
			byte[] raw = key.getBytes("utf8");
			SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] encrypted1 = StringUtils.hex2Bytes(content);
			byte[] original = cipher.doFinal(encrypted1);
			return new String(original, "utf-8");
		} catch (Exception ex) {
			return null;
		}
	}

	/**
	 * 解密
	 * 
	 * @param content 待解密的内容
	 * @param key     解密秘钥
	 * @return 解密后的内容.字节数组
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] content, String key) throws Exception {
		try {
			byte[] raw = key.getBytes("utf8");
			SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(content);

			return original;
		} catch (Exception ex) {
			return null;
		}
	}
}