package com.wzjwhut.example;

import com.wzjwhut.util.CipherUtil;
import com.wzjwhut.util.DigestUtil;
import com.wzjwhut.util.ECCP256R1l;
import com.wzjwhut.util.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Arrays;

/** 解密分析TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.pcapng
 * 先使用wireshark解析出基本参数
 * 使用已知的证书/公钥/私钥 来分析握手过程 */
public class Analyse_ECDHE_RSA_WITH_AES_128_CBC_SHA256 {
    private final static Logger logger = LogManager.getLogger(Analyse_ECDHE_RSA_WITH_AES_128_CBC_SHA256.class);

    //random 由4字节的时间戳和28字节的随机数据组成. 共32字节. openssl的时间戳好像是乱写的
    public static final byte[] clientRandom = HexUtils.fromHexString(
            "8f fa 98 06 3f 44 81 c6 b8 5f 7d ef c8 33 2f bb\n" +
            "f3 9e 8b b7 46 ac ce f7 a3 60 de 3f b3 da c5 2d\n");

    public static final byte[] serverRandom = HexUtils.fromHexString(
            "5c 4c 1b 29 0b 94 45 f9 0d 3c 9b 7a c4 67 68 d5\n" +
            "94 f0 c8 78 3e e4 c9 e0 da 3c 6e bc a4 af 17 30\n");

    static BigInteger clientPrivateKey = new BigInteger(HexUtils.fromHexString(
            "00" +
            "61 b4 7c 58 92 26 fc 4e aa 82 8d ee 86 d3 c5 33\n" +
                    "65 a6 aa c0 ae db c5 e3 07 ef 29 3e 22 fd c1 6a"));

    static BigInteger serverPublicKeyX = new BigInteger(HexUtils.fromHexString(
            "3d 0f 6c 38 35 8e 0b 5b 1e 3b 2c 2b 0e d5 b7\n" +
                    "1d f5 8d d3 51 f8 2d 80 b8 f4 4c b9 12 5d 33 36\n" +
                    "26 "));
    static BigInteger serverPublicKeyY = new BigInteger(HexUtils.fromHexString(
            "00" +
            "fb b1 d5 b9 55 ce 8c 3c 34 f0 7b 9a 48 2c 5a\n" +
                    "3c 89 4b dd 04 56 63 08 71 34 a5 7a 83 a7 83 1e\n" +
                    "2b"));

    static byte[] clientEncryptedAppData = HexUtils.fromHexString(
            "83 b4 75 be 10 5f 5f 25 66 07 fa 06 aa 2d 68 58\n" +
            "bd 65 d0 07 59 d7 dd fc 9a cf 81 24 0b 26 e9 81\n" +
            "3e ff 7c 23 15 5c b4 37 c7 0e 43 27 b2 cc c4 9c\n" +
            "63 54 5b 71 a8 b2 79 75 b8 bd 0a c2 14 72 72 88");

    /** 使用DH算法, 计算出pre master */
    public static byte[] computePreMaster() throws Exception{
        /** ecdh计算太复杂了, 直接系统接口吧 */
        byte[] sharedKey = CipherUtil.ecdhShareKey(clientPrivateKey, serverPublicKeyX, serverPublicKeyY);
        logger.info("system shared key: \r\n{}", HexUtils.dumpString(sharedKey, 16));
//        return sharedKey;

        /** 使用开源库计算. 使用对方的Point乘上自己的私钥 */
        byte[] myKey = ECCP256R1l.multi(serverPublicKeyX, serverPublicKeyY, clientPrivateKey);
        logger.info("my shared key: \r\n{}", HexUtils.dumpString(myKey, 16));
        return myKey;
    }


    public static byte[] PRF(byte[] secret, byte[] label, byte[] seed, int outBytes) throws Exception{
        //SHA-256每次产生32字节数字
        seed = HexUtils.join(label, seed);
        int c = (outBytes+32-1)/32;
        byte[][] buf = new byte[c][32];
        byte[] preA = seed;
        for(int i=0; i<c; i++){
            byte[] Ai = DigestUtil.hmacsha256(preA, secret);
            buf[i] = DigestUtil.hmacsha256(HexUtils.join(Ai, seed), secret);
            preA = Ai;
        }
        return Arrays.copyOf(HexUtils.join(buf), outBytes);
    }


    /**
    公式为
     master_secret = PRF(pre_master_secret, "master secret",ClientHello.random + ServerHello.random)
     master_secret固定48字节
     PRF为伪随机数算法, TLS v1.2使用SHA-256
     */
    public static byte[] computeMasterSecret(byte[] premaster) throws Exception{
        return PRF(premaster,
                "master secret".getBytes(),
                HexUtils.join(clientRandom , serverRandom), 48);
    }

    public static void main(String[] arsg) throws Exception{
        byte[] premaster = computePreMaster();
        logger.info("computed pre master: \r\n{}", HexUtils.dumpString(premaster, 16));
        byte[] masterSecret = computeMasterSecret(premaster);
        logger.info("master key: \r\n{}", HexUtils.dumpString(masterSecret, 16));

        byte[] keyBlock = PRF(masterSecret, "key expansion".getBytes(),
                HexUtils.join(serverRandom, clientRandom), 96);
        logger.info("keyblock: \r\n{}", HexUtils.dumpString(keyBlock, 16));

        byte[] clientMacKey = Arrays.copyOfRange(keyBlock, 0, 32);
        byte[] serverMacKey = Arrays.copyOfRange(keyBlock, 32, 64);
        byte[] clientAESKey = Arrays.copyOfRange(keyBlock, 64, 64+16);
        byte[] serverAESKey = Arrays.copyOfRange(keyBlock, 64+16, 64+16+16);

        {
            byte[] iv = Arrays.copyOf(clientEncryptedAppData, 16);
            byte[] content = Arrays.copyOfRange(clientEncryptedAppData, 16, clientEncryptedAppData.length);
            byte[] decrypted = CipherUtil.cbcDecrypt(clientAESKey, iv, content);
            logger.info("decrypted application msg: \r\n{}", HexUtils.dumpString(decrypted, 16));
            logger.info("decrypted: \r\n{}", new String(decrypted));
        }
    }
}
