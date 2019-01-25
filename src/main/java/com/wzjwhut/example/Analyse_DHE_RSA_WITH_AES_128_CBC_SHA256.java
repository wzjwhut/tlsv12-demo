package com.wzjwhut.example;

import com.wzjwhut.util.CipherUtil;
import com.wzjwhut.util.DigestUtil;
import com.wzjwhut.util.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Arrays;

/** 解密分析TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.pcapng
 * 先使用wireshark解析出基本参数
 * 使用已知的证书/公钥/私钥 来分析握手过程 */
public class Analyse_DHE_RSA_WITH_AES_128_CBC_SHA256 {
    private final static Logger logger = LogManager.getLogger(Analyse_DHE_RSA_WITH_AES_128_CBC_SHA256.class);

    //random 由4字节的时间戳和28字节的随机数据组成. 共32字节. openssl的时间戳好像是乱写的
    public static final byte[] clientRandom = HexUtils.fromHexString(
            "64 61 aa 72 dd 0a d6 2b 42 11 c4 f6 45 40 cf f4\n" +
            "c2 eb f3 37 55 8e c7 d0 91 04 06 2d f4 85 ce 55\n");

    public static final byte[] serverRandom = HexUtils.fromHexString(
            "5c 4a b2 c7 3d d5 c1 16 52 e7 48 ea 79 d4 3e 7e\n" +
            "8c 81 21 37 82 4a 8d 0b cf a7 e1 16 7c bf e8 0e\n");

    /** 解密之后的最后48字节才是pre master. 原因不明 */
    public static final BigInteger DH_P = new BigInteger(HexUtils.fromHexString(
            "00 " + //为了保证BigInteger按照正数解析, 第1个字节必须为0
            "ff ff ff ff ff ff ff ff c9 0f da a2 21 68 c2 34\n" +
            "c4 c6 62 8b 80 dc 1c d1 29 02 4e 08 8a 67 cc 74\n" +
            "02 0b be a6 3b 13 9b 22 51 4a 08 79 8e 34 04 dd\n" +
            "ef 95 19 b3 cd 3a 43 1b 30 2b 0a 6d f2 5f 14 37\n" +
            "4f e1 35 6d 6d 51 c2 45 e4 85 b5 76 62 5e 7e c6\n" +
            "f4 4c 42 e9 a6 37 ed 6b 0b ff 5c b6 f4 06 b7 ed\n" +
            "ee 38 6b fb 5a 89 9f a5 ae 9f 24 11 7c 4b 1f e6\n" +
            "49 28 66 51 ec e6 53 81 ff ff ff ff ff ff ff ff"));

    /** G通常是固定值 */
    public static final BigInteger DH_G = BigInteger.valueOf(2);

    /** PUBKEY = g^privkey mod p */
    public static final BigInteger DH_SERVER_PUBKEY = new BigInteger(HexUtils.fromHexString(
            "78 8d 66 69 7b bf c9 01 f8 2c f0 02 cc 5b 70 cf\n" +
            "af 53 4e 65 26 19 16 48 21 7d 43 50 2f af a1 8c\n" +
            "e8 c9 7c c6 52 f9 a9 fc f9 8d 57 35 e9 c2 d6 41\n" +
            "75 4d 96 15 fa ae 3e 90 b5 47 96 1c 7e e9 10 46\n" +
            "d7 25 73 f7 c6 f2 7b c0 10 3f 76 ab 5c c5 fd 65\n" +
            "ec d0 8f 36 c9 28 66 3f 64 78 84 9c 5a 16 17 8e\n" +
            "78 f5 30 d1 11 f9 d3 19 fa f8 83 2e 97 50 f7 d4\n" +
            "7a 70 b2 10 c2 db 45 73 e6 ef 8a 1c 27 a2 73 86"));

    public static final BigInteger DH_CLIENT_PUBKEY = new BigInteger(HexUtils.fromHexString(
            "d0 c1 af 38 0b 94 93 df 22 e5 be 3e d6 92 a2 80\n" +
            "ef 03 f0 75 d1 4c ab a0 83 e8 8f f6 3f 9d c5 3e\n" +
            "3a 38 4e 3a 67 a2 89 d7 bb 4a 63 41 b1 1d 07 e7\n" +
            "12 64 a8 60 72 75 f0 92 cb a2 e4 13 e5 ab 7f 28\n" +
            "1a c5 4a 8a bc a5 0a 82 c0 b0 78 ad 0d ce 1d b0\n" +
            "dd 7a 90 70 24 50 23 73 18 13 d0 90 14 ce 03 35\n" +
            "24 16 ac 21 b8 34 f7 96 30 61 63 0c 79 2b b6 79\n" +
            "d8 11 31 d0 02 cc 89 19 f7 90 e7 db 48 eb fb 9b\n"));


    public static final BigInteger DH_CLIENT_PRIVKEY = new BigInteger(HexUtils.fromHexString(
            "57 99 8b f0 c8 9b bd 7f 42 3a 57 c8 e6 ad 10 80\n" +
            "ad 5e 25 7f e9 a3 c0 ea cc 28 21 35 bb f5 88 69\n" +
            "d0 9c 03 0e a6 d3 9a 5d 93 5a 6b ff 0e aa 93 91\n" +
            "a2 93 f9 5d fd dd a9 fa 26 e9 4a cd b3 17 b9 ab\n" +
            "f9 b8 72 38 90 3c 0e 50 b2 b4 4a 40 61 dd 45 64\n" +
            "f9 d2 cc d3 26 b3 e3 5c ac 02 0d 31 91 2a f5 46\n" +
            "e3 58 70 6b 62 68 a3 be 93 7d 41 1b 1b a9 73 35\n" +
            "1b 52 60 3d f8 d1 45 94 3c ff 76 bf a1 9a 07 7d"));

    public static final byte[] clientEncryptedAppData = HexUtils.fromHexString(
            "31 3f 58 10 1a 52 74 4e c7 0f 02 b3 e1 9d ae e4\n" +
            "64 09 b6 61 23 12 08 a6 dd bb 40 6b 76 51 92 d9\n" +
            "77 c8 05 28 9f 09 8f cd bc cc 05 e8 d5 dc 10 dc\n" +
            "9a ac 23 54 53 9c 2c 97 f1 5b 4a 9a 10 50 38 16\n" +
            "82 13 a6 4c 9b 8c bf 6f 84 cc fa 95 76 e7 e8 30\n" +
            "3b f9 0e cc 01 1f e2 6e 70 b9 57 00 11 5b 55 98");

    /** 使用DH算法, 计算出pre master */
    public static byte[] computePreMaster(){
        byte[] preMaster = DH_SERVER_PUBKEY.modPow(DH_CLIENT_PRIVKEY, DH_P).toByteArray();
        logger.info("premaster:\r\n{}", HexUtils.dumpString(preMaster, 16));
        return preMaster;
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

    /*
      struct {
          opaque IV[SecurityParameters.record_iv_length];
          block-ciphered struct {
              opaque content[TLSCompressed.length];
              opaque MAC[SecurityParameters.mac_length];
              uint8 padding[GenericBlockCipher.padding_length];
              uint8 padding_length;
          };
      } GenericBlockCipher;


    key_block = PRF(SecurityParameters.master_secret,
                      "key expansion",
                      SecurityParameters.server_random +
                      SecurityParameters.client_random);


    client_write_MAC_key[SecurityParameters.mac_key_length]
      server_write_MAC_key[SecurityParameters.mac_key_length]
      client_write_key[SecurityParameters.enc_key_length]
      server_write_key[SecurityParameters.enc_key_length]
      client_write_IV[SecurityParameters.fixed_iv_length]
      server_write_IV[SecurityParameters.fixed_iv_length]

      mac_length = 32, sha256
      mac_key_length = 32,
      enc_key_length  = 16 , CBC128
      这里的IV没有用.
      key_block长度为 32 + 32 + 16 + 16 = 96.
    */

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
