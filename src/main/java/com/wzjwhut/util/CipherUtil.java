package com.wzjwhut.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
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

    public static KeyPair genECCKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(spec, new SecureRandom());
        KeyPair pair = keyPairGenerator.generateKeyPair();
        return pair;
    }

    public static KeyPair genDHKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(1024);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        return pair;
    }

    public static KeyPair genRSAKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
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

    public static void main(String[] args) throws Exception{
//        {
//            KeyPair clientECKeyPair = genECCKeyPair();
//            long time = System.currentTimeMillis();
//            for (int i = 0; i < 1 * 10000; i++) {
//                KeyPair serverECKeyPair = genECCKeyPair();
//                KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
//                keyAgreement.init(serverECKeyPair.getPrivate());
//                keyAgreement.doPhase(clientECKeyPair.getPublic(), true);
//                keyAgreement.generateSecret();
//            }
//            logger.info("time: {}", System.currentTimeMillis() - time);
//        }
//        {
//            KeyPair clientKeyPair = genDHKeyPair();
//            long time = System.currentTimeMillis();
//            for (int i = 0; i < 1 * 10000; i++) {
//                KeyPair serverKeyPair = genDHKeyPair();
//                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
//                keyAgreement.init(serverKeyPair.getPrivate());
//                keyAgreement.doPhase(clientKeyPair.getPublic(), true);
//                keyAgreement.generateSecret();
//            }
//            logger.info("time: {}", System.currentTimeMillis() - time);
//        }

        {
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
            logger.info("time: {}", System.currentTimeMillis() - time);
        }
    }

}
