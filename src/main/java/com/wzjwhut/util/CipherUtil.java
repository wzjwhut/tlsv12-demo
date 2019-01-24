package com.wzjwhut.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class CipherUtil {
    private final static Logger logger = LogManager.getLogger(CipherUtil.class);

    public static byte[] cbcEncrypt(byte[] key, byte[] iv, byte[] input) throws Exception {
        key = Arrays.copyOf(key, 16);
        input = Arrays.copyOf(input, 16);
        iv = Arrays.copyOf(iv, 16);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] result = cipher.doFinal(input);
        return result;
    }

    public static byte[] cbcDecrypt(byte[] key, byte[] iv, byte[] cipherContent) throws Exception {
        key = Arrays.copyOf(key, 16);
        iv = Arrays.copyOf(iv, 16);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher decoder = Cipher.getInstance("AES/CBC/NoPadding");
        decoder.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] out = decoder.doFinal(cipherContent);
        //logger.info("[decrypt] input: \r\n{}, out:{}\r\n{}", HexUtils.dumpString(cipherContent),out.length,  HexUtils.dumpString(out));
        return out;
    }

    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws Throwable {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }

    public static void main(String[] args) throws Exception{
        byte[] input = {1, 7, 9};
        byte[] iv = {1,2};
        byte[] key = {3, 4};
        byte[] encrypted = cbcEncrypt(key, iv, input);
        byte[] decrypted = cbcDecrypt(key, iv, encrypted);
        logger.info("decrypted: {}", decrypted);
    }

}
