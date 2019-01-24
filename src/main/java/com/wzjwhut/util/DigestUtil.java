package com.wzjwhut.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestUtil {
    private final static Logger logger = LogManager.getLogger(DigestUtil.class);

    public static String sha1(String text) throws Exception {
        if (StringUtils.isBlank(text)) {
            return "";
        }
        MessageDigest digest;
        digest = MessageDigest.getInstance("SHA1");
        digest.update(text.getBytes(StandardCharsets.UTF_8));
        return HexUtils.hexString(digest.digest());
    }

    public static byte[] sha256(byte[] text) throws Exception {
        MessageDigest digest;
        digest = MessageDigest.getInstance("SHA-256");
        digest.update(text);
        return digest.digest();
    }

    public static String sha256(String text) throws Exception {
        if (StringUtils.isBlank(text)) {
            return "";
        }
        MessageDigest digest;

        digest = MessageDigest.getInstance("SHA-256");
        digest.update(text.getBytes(StandardCharsets.UTF_8));
        return HexUtils.hexString(digest.digest());
    }

    public static byte[] hmacsha1(String src, String key) throws Exception {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("utf-8"), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        return mac.doFinal(src.getBytes("utf-8"));
    }

    public static byte[] hmacsha1(byte[] src, byte[] key) throws Exception {
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        return mac.doFinal(src);
    }

    public static byte[] hmacsha256(byte[] src, byte[] key) throws Exception {
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(signingKey);
        return mac.doFinal(src);
    }


    public static void main(String[] args) throws Exception{
        logger.info("{}", HexUtils.dumpString(hmacsha256("123".getBytes(), "1234".getBytes())));
    }










}











