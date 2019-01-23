package com.wzjwhut.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class HmacSha1Util {
    private final static Logger logger = LogManager.getLogger(HmacSha1Util.class);
    public static byte[] hmacSha1(String src, String key) throws Exception {
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("utf-8"), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
            return mac.doFinal(src.getBytes("utf-8"));
    }

    public static byte[] hmacSha1(byte[] src, byte[] key) throws Exception {
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        return mac.doFinal(src);
    }
}
