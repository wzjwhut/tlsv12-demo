package com.wzjwhut.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
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

    public static void genECCKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(spec, new SecureRandom());
        KeyPair pair = keyPairGenerator.generateKeyPair();
        logger.info("ec private key: {}, {}", pair.getPrivate().toString(), pair.getPublic().getClass());
        logger.info("ec pubic key: {}", pair.getPublic().toString());
    }

    public static ECParameterSpec getECParameterSpec(String name) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(name));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }
    public static void buildECPublicKey(BigInteger x, BigInteger y) throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECPublicKeyImpl publicKey = new ECPublicKeyImpl(new ECPoint(x, y), getECParameterSpec("secp256r1"));
        logger.info("ec pubic key: {}", publicKey);
    }

    public static byte[] ecdhShareKey(BigInteger k, BigInteger publicKeyPointX, BigInteger publicKeyPointY) throws Exception{
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        logger.info("key agreement: {}", keyAgreement.getClass());
        ECParameterSpec ecparams = getECParameterSpec("secp256r1");
        ECPublicKeyImpl publicKey = new ECPublicKeyImpl(new ECPoint(publicKeyPointX, publicKeyPointY), ecparams);
        ECPrivateKeyImpl privateKey = new ECPrivateKeyImpl(k, ecparams);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }


    public static void testCBC() throws Exception{
        byte[] input = {1, 7, 9};
        byte[] iv = {1, 2};
        byte[] key = {3, 4};
        byte[] encrypted = cbcEncrypt(key, iv, input);
        byte[] decrypted = cbcDecrypt(key, iv, encrypted);
        logger.info("decrypted: {}", decrypted);
    }

    static BigInteger gPrivteKey = new BigInteger(HexUtils.fromHexString(
            "61 b4 7c 58 92 26 fc 4e aa 82 8d ee 86 d3 c5 33\n" +
            "65 a6 aa c0 ae db c5 e3 07 ef 29 3e 22 fd c1 6a"));
    static BigInteger publicKeyX = new BigInteger(HexUtils.fromHexString(
            "3d 0f 6c 38 35 8e 0b 5b 1e 3b 2c 2b 0e d5 b7\n" +
                    "1d f5 8d d3 51 f8 2d 80 b8 f4 4c b9 12 5d 33 36\n" +
                    "26 "));
    static BigInteger publicKeyY = new BigInteger(HexUtils.fromHexString(
            "fb b1 d5 b9 55 ce 8c 3c 34 f0 7b 9a 48 2c 5a\n" +
                    "3c 89 4b dd 04 56 63 08 71 34 a5 7a 83 a7 83 1e\n" +
                    "2b"));

    public static void main(String[] args) throws Exception{
        //buildECPublicKey(BigInteger.valueOf(1L), BigInteger.valueOf(1L));
        byte[] sharedKey = ecdhShareKey(gPrivteKey, publicKeyX, publicKeyY);
        logger.info("shared ecdh key: {}", HexUtils.dumpString(sharedKey, 16));
    }

}
