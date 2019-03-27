package com.wzjwhut.util;

import com.sun.crypto.provider.DHKeyPairGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.ec.ECKeyPairGenerator;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;
import sun.security.rsa.RSAKeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
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
import java.util.Random;

public class CipherUtil {
    private final static Logger logger = LogManager.getLogger(CipherUtil.class);

    private final static SecureRandom RANDOM = new SecureRandom();


    public static byte[] DESEncrypt(byte[] key, byte[] iv, byte[] input) throws Exception {
        if(key.length != 24) {
            key = Arrays.copyOf(key, 16);
        }
        if(input.length<16) {
            input = Arrays.copyOf(input, 16);
        }
        if(iv.length != 8) {
            iv = Arrays.copyOf(iv, 8);
        }
        SecretKeySpec secretKey = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] result = cipher.doFinal(input);
        return result;
    }

    public static byte[] DESDecrypt(byte[] key, byte[] iv, byte[] cipherContent) throws Exception {
        if(key.length != 24) {
            key = Arrays.copyOf(key, 16);
        }
        if(iv.length != 8) {
            iv = Arrays.copyOf(iv, 8);
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
        Cipher decoder = Cipher.getInstance("DESede/CBC/NoPadding");
        decoder.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] out = decoder.doFinal(cipherContent);
        //logger.info("[decrypt] input: \r\n{}, out:{}\r\n{}", HexUtils.dumpString(cipherContent),out.length,  HexUtils.dumpString(out));
        return out;
    }


    public static byte[] aesGCMEncrypt(byte[] key, byte[] iv, byte[] input) throws Exception {
        if(key.length != 16) {
            key = Arrays.copyOf(key, 16);
        }
        if(input.length != 16) {
            input = Arrays.copyOf(input, 16);
        }
        if(iv.length != 16) {
            iv = Arrays.copyOf(iv, 16);
        }
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(16 * Byte.SIZE, iv));
        byte[] result = cipher.doFinal(input);
        return result;
    }

    public static byte[] aesGCMDecrypt(byte[] key, byte[] iv, byte[] cipherContent) throws Exception {
        if(key.length != 16) {
            key = Arrays.copyOf(key, 16);
        }
        if(iv.length != 16) {
            iv = Arrays.copyOf(iv, 16);
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher decoder = Cipher.getInstance("AES/GCM/NoPadding");
        decoder.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * Byte.SIZE, iv));
        byte[] out = decoder.doFinal(cipherContent);
        //logger.info("[decrypt] input: \r\n{}, out:{}\r\n{}", HexUtils.dumpString(cipherContent),out.length,  HexUtils.dumpString(out));
        return out;
    }


    public static byte[] cbcEncrypt(byte[] key, byte[] iv, byte[] input) throws Exception {
        if(key.length!=16) {
            key = Arrays.copyOf(key, 16);
        }
        if(input.length!=16) {
            input = Arrays.copyOf(input, 16);
        }
        if(iv.length!=16) {
            iv = Arrays.copyOf(iv, 16);
        }
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] result = cipher.doFinal(input);
        return result;
    }

    public static byte[] cbcDecrypt(byte[] key, byte[] iv, byte[] cipherContent) throws Exception {
        if(key.length != 16) {
            key = Arrays.copyOf(key, 16);
        }
        if(iv.length != 16) {
            iv = Arrays.copyOf(iv, 16);
        }
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

    public static KeyPair genECCKeyPair() throws Throwable {
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(spec, new SecureRandom());
        KeyPair pair = keyPairGenerator.generateKeyPair();
        return pair;
    }

    public static KeyPair genDHKeyPair() throws Exception {
        //KeyPairGenerator keyPairGeneator = KeyPairGenerator.getInstance("DH");
        //keyPairGeneator.initialize(1024);
        DHKeyPairGenerator keyPairGeneator = new DHKeyPairGenerator();
        keyPairGeneator.initialize(1024, RANDOM);
        KeyPair pair = keyPairGeneator.generateKeyPair();
        return pair;
    }

    public static KeyPair genRSAKeyPair() throws Exception {
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.initialize(2048, RANDOM);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static ECParameterSpec getECParameterSpec(String name) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(name));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    public static void buildECPublicKey(BigInteger x, BigInteger y) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECPublicKeyImpl publicKey = new ECPublicKeyImpl(new ECPoint(x, y), getECParameterSpec("secp256r1"));
        logger.info("ec pubic key: {}", publicKey);
    }

    public static byte[] ecdhShareKey(BigInteger k, BigInteger publicKeyPointX, BigInteger publicKeyPointY) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        logger.info("key agreement: {}", keyAgreement.getClass());
        ECParameterSpec ecparams = getECParameterSpec("secp256r1");
        ECPublicKeyImpl publicKey = new ECPublicKeyImpl(new ECPoint(publicKeyPointX, publicKeyPointY), ecparams);
        ECPrivateKeyImpl privateKey = new ECPrivateKeyImpl(k, ecparams);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public static void DHEPerformance() throws Throwable {
        KeyPair clientKeyPair = genDHKeyPair();
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 10000; i++) {
            KeyPair serverKeyPair = genDHKeyPair();
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(serverKeyPair.getPrivate());
            keyAgreement.doPhase(clientKeyPair.getPublic(), true);
            keyAgreement.generateSecret();
        }
        logger.info("[DHE] time: {}", System.currentTimeMillis() - time);
    }

    public static void RSAPerformance() throws Throwable {
        KeyPair serverKeyPair = genRSAKeyPair();
        Random r = new Random();
        byte[] preMaster = new byte[48];
        r.nextBytes(preMaster);
        Cipher encoder = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encoder.init(Cipher.ENCRYPT_MODE, serverKeyPair.getPublic());
        encoder.update(preMaster);
        byte[] encryptedPreMaster = encoder.doFinal();
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 10000; i++) {
            Cipher decryptor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptor.init(Cipher.DECRYPT_MODE, serverKeyPair.getPublic());
            decryptor.update(encryptedPreMaster);
        }
        logger.info("[RSA] time: {}", System.currentTimeMillis() - time);
    }

    public static void ECDHEPerformance() throws Throwable {
        KeyPair clientPair = genECCKeyPair();
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 10000; i++) {
            KeyPair serverPair = genECCKeyPair();
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(serverPair.getPrivate());
            keyAgreement.doPhase(clientPair.getPublic(), true);
            keyAgreement.generateSecret();
        }
        logger.info("[ECDHE] time: {}", System.currentTimeMillis() - time);
    }

    public static void ECDHPerformance() throws Throwable {
        KeyPair clientPair = genECCKeyPair();
        long time = System.currentTimeMillis();
        KeyPair serverPair = genECCKeyPair();
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(serverPair.getPrivate());
        keyAgreement.doPhase(clientPair.getPublic(), true);
        for (int i = 0; i < 1 * 10000; i++) {
            keyAgreement.generateSecret();
        }
        logger.info("[ECDH] time: {}", System.currentTimeMillis() - time);
    }

    public static void aesGCMPerformance() throws Throwable {
        byte[] key = new byte[16];
        byte[] input = new byte[16];
        byte[] iv = new byte[16];
        for(byte i=0; i<16; i++){
            key[i] = i;
            input[i] = i;
            iv[i] = i;
        }
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 100000; i++) {
            byte[] out = aesGCMEncrypt(key, iv, input);
            aesGCMDecrypt(key, iv, out);
        }
        logger.info("[AES GCM] time: {}", System.currentTimeMillis() - time);
    }

    public static void aesCBCPerformance() throws Throwable {
        byte[] key = new byte[16];
        byte[] input = new byte[16];
        byte[] iv = new byte[16];
        for(byte i=0; i<16; i++){
            key[i] = i;
            input[i] = i;
            iv[i] = i;
        }

        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 100000; i++) {
            byte[] out = cbcEncrypt(key, iv, input);
            cbcDecrypt(key, iv, out);
        }
        logger.info("[AES CBC] time: {}", System.currentTimeMillis() - time);
    }

    public static void DESPerformance() throws Throwable {
        byte[] key = new byte[24];
        byte[] input = new byte[16];
        byte[] iv = new byte[16];
        for(byte i=0; i<16; i++){
            key[i] = i;
            input[i] = i;
            iv[i] = i;
        }
        iv = Arrays.copyOf(iv, 8);
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 100000; i++) {
            byte[] out = DESEncrypt(key, iv, input);
            DESDecrypt(key, iv, out);
        }
        logger.info("[DES CBC] time: {}", System.currentTimeMillis() - time);
    }

    public static void hmacSha256Performance() throws Throwable{
        byte[] key = new byte[48];
        byte[] input = new byte[128];
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 100000; i++) {
            DigestUtil.hmacsha256(input, key);
        }
        logger.info("[hmacSha256] time: {}", System.currentTimeMillis() - time);
    }

    public static void hmacShaPerformance() throws Throwable{
        byte[] key = new byte[48];
        byte[] input = new byte[128];
        long time = System.currentTimeMillis();
        for (int i = 0; i < 1 * 100000; i++) {
            DigestUtil.hmacsha1(input, key);
        }
        logger.info("[hmacSha1] time: {}", System.currentTimeMillis() - time);
    }


    public static void main(String[] args) throws Throwable {
//        DHEPerformance();
//        ECDHEPerformance();
//        ECDHPerformance();
//        RSAPerformance();
        aesGCMPerformance();
        aesCBCPerformance();
        DESPerformance();

        hmacSha256Performance();
        hmacShaPerformance();
    }

}
