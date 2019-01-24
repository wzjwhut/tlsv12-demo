package com.wzjwhut.example;

import com.wzjwhut.util.CipherUtil;
import com.wzjwhut.util.DigestUtil;
import com.wzjwhut.util.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Arrays;

/** 帮助分析抓包到的数据, TLS_RSA_WITH_AES_128_CBC_SHA256.pcapng
 * 先使用wireshark解析出基本参数
 * 使用已知的证书/公钥/私钥 来分析握手过程 */
public class Parse_RSA_WITH_AES_128_CBC_SHA256 {
    private final static Logger logger = LogManager.getLogger(Parse_RSA_WITH_AES_128_CBC_SHA256.class);

    //random 由4字节的时间戳和28字节的随机数据组成. 共32字节
    public static final byte[] clientRandom = HexUtils.fromHexString(
            "5c 48 6a 33 93 14 eb 56 d2 7d 86 07 56 83 80 95\n" +
            "ff 1e 3c 32 b4 21 d0 70 ab e2 fb a0 6a b2 6a 3f\n");

    public static final byte[] serverRandom = HexUtils.fromHexString(
            "5c 48 6a 36 a6 57 51 c6 13 a2 88 df 39 a0 42 02\n" +
            "9c 7b 35 cb 4f 55 5d 91 3c 7f 89 e2 c6 21 e2 eb\n");

    /** 如果是使用RSA交换密钥, 才会出现.
     使用公钥加密以下结构体, 产生reMaster;
     struct {
             ProtocolVersion client_version; //两个字节
             opaque random[46];
     } PreMasterSecret;
     */

    /** 解密之后的最后48字节才是pre master. 原因不明 */
    public static final byte[] clientEncryptedPreMaster = HexUtils.fromHexString(
            "69 8d 0e 95 67 40 6b ae 0f cb 7e c1 59 34 c4 93\n" +
                    "ba a1 ae bb 64 e7 84 e3 54 bc 1e ed 9c 8a 96 7a\n" +
                    "f1 51 58 56 28 9b 1a a8 fa a2 e5 0b 2c 0c 20 36\n" +
                    "37 55 9c 9d 5f 1a 76 19 18 6e 65 f0 e5 88 19 99\n" +
                    "04 b4 49 31 af ce 30 08 22 f5 89 ed cf 32 5b 01\n" +
                    "32 b8 76 7e 0d 27 98 f2 df 7e 6c 88 5f 96 14 fd\n" +
                    "4d ff e5 b6 0d 50 da e6 72 f3 c9 18 52 10 e8 d9\n" +
                    "c8 c6 78 03 b6 bf 07 11 60 95 14 77 34 6d c0 c9\n" +
                    "4c 5d 4c 25 25 78 68 70 62 3f a9 21 35 f5 f0 46\n" +
                    "34 21 3a e0 63 56 a0 84 64 e5 9e d4 b9 fe 1a c4\n" +
                    "d4 6d 31 70 4f da ae c5 ee 70 62 db 16 00 b7 f4\n" +
                    "c0 3b ce ad 44 fd a6 1a eb 7f 8b 1c 03 91 47 b9\n" +
                    "15 69 5e 70 e8 6b d1 82 ae d8 b6 76 c3 c5 ba 56\n" +
                    "e2 87 ee bc 73 c4 3c 7a 67 8a 2f 14 e4 ea d4 67\n" +
                    "73 8b ea 9a 7c fb ac e4 a3 d9 cf 4e 81 ba b4 0c\n" +
                    "2d 87 02 fa 82 f6 f3 53 b6 f6 45 26 26 1a 1d 02");

    public static final byte[] clientEncryptedHandShakeMessage = HexUtils.fromHexString(
            "22 96 1f c2 56 c4 12 48 b0 91 b6 e5 7c b8 1f 0a\n" +
            "40 e9 b6 ee b6 25 76 71 58 37 d4 37 f9 65 e7 a5\n" +
            "80 94 bb b3 d8 78 c5 a9 c4 b8 29 94 27 da 82 41\n" +
            "e8 22 d6 38 55 48 51 17 6c 8e e8 44 9e 6a 9c aa\n" +
            "68 14 66 eb 95 7d 73 9d cc 47 ac ae 69 c9 b6 73\n");

    public static final byte[] serverEncryptedHandShakeMessage = HexUtils.fromHexString(
            "13 d7 58 d3 6b 1b 48 b3 e0 a9 2d 62 e0 48 93 00\n" +
            "1b db b8 1a 24 c0 8e 9d 68 44 a1 24 87 2a 12 e7\n" +
            "5e 77 d9 5d d9 23 df 3e e6 56 c5 48 e4 6c a3 bf\n" +
            "02 76 6c 4f 89 c2 02 f6 73 84 6c 3c 7c 32 cb fd\n" +
            "5d 2c 80 2e b2 14 6c e6 59 39 c6 af 6f c3 57 57");

    public static final byte[] clientEncryptedAppData = HexUtils.fromHexString(
            "a1 25 35 e9 f6 82 6b a1 8f 05 c6 84 bc c0 85 ed\n" +
                    "b2 b8 f3 0d 2a 4b 95 64 54 6c 54 e0 68 47 fc 57\n" +
                    "45 8f 25 6d a3 5a d6 a2 eb b4 42 a8 11 cf 5b 0d\n" +
                    "4a c1 b0 4f d6 40 75 44 ac 78 94 da ca 58 8d 2a\n" +
                    "12 a9 48 b6 4d 4c 4f 64 df 67 24 96 76 d6 b7 d2\n" +
                    "43 c3 ef 50 60 0a cf 3c ba a5 0e 64 4b 4d da ad\n" +
                    "1b 3d f3 e0 ed 9d b1 e4 ae 7b 2b 40 58 0f 74 32\n" +
                    "0c ee 69 34 35 e2 45 9f 2f 62 aa d8 e8 02 00 34\n" +
                    "63 bd ef 68 bc a4 0c 3a 56 38 ca 9c e4 9a 76 1c\n" +
                    "28 63 60 d4 2e a6 da aa 4f 30 b0 2d a1 83 83 21\n" +
                    "b0 07 13 20 bb 54 4c 42 35 fa b7 86 f6 3f fd df\n" +
                    "ee 1d 8d 0d 1b 23 e7 14 73 bd 30 ce 79 9b db d5\n" +
                    "c2 71 e8 06 fa 4a 2b 2a d0 d1 8e 76 5a 61 75 5f\n" +
                    "f0 04 44 ad 36 63 65 48 6d 7b d3 70 bb 36 69 03\n" +
                    "\n");
    public static final byte[] serverEncryptedAppData = HexUtils.fromHexString(
            "de 79 1f 4f 91 2d 93 49 a4 a1 5e bd 76 a5 4a 17\n" +
            "75 e8 2e 30 78 f6 bb 1e 6f 6d a3 8f 39 06 ea 52\n" +
            "82 1c f1 a7 45 ab fa 7d 2a f5 26 cf 80 6b dc 92\n" +
            "8b 5d 45 a4 e3 1c df 6e e7 67 e8 54 a3 e9 a4 c1\n" +
            "8c 93 6a ed a5 7f 67 bb 90 96 84 fc 08 c2 16 be\n" +
            "9e c7 ec e9 b3 0e 5b 05 bf 14 a4 78 21 b3 fc 1b\n" +
            "97 1d 38 ee ca 14 b0 67 81 8e 5f 3a 41 f9 03 5a\n" +
            "36 70 4b c0 c8 d1 a2 b4 ac b6 b0 1a c9 e2 6e 03\n" +
            "00 92 87 6d d2 63 bb c3 e2 4e 42 5a e9 f3 99 b2\n" +
            "49 6b 14 ca 4e f3 4e 2d b0 78 46 a5 0d 25 e8 29\n" +
            "3e b3 ba dc e6 e1 8a 2d d1 ba 73 5f ac 5b 60 05\n" +
            "8a 05 9b bf 84 07 87 c7 7f 6f fd fd a0 2d a4 3a\n" +
            "13 c3 35 59 67 89 b9 22 5e a8 ee b2 a8 42 fa d5\n" +
            "8d 67 6b 53 11 16 0d 5d 62 0f fa f3 4f ed e9 f3\n" +
            "cd 21 70 87 54 a9 a3 85 45 ec c1 61 a7 1f d7 a9\n" +
            "1f 51 6c c8 93 b6 70 52 15 aa 9b d4 91 f7 1c 6e\n" +
            "e5 a4 e3 cd 63 d2 fd 19 ed 41 2b aa 98 8b 7d ba\n" +
            "0e 5b d4 a3 19 b8 f8 71 1c e5 ce 65 eb 95 aa 6e\n" +
            "02 48 55 0e 2e f1 7e 95 af d3 71 5b a6 27 38 4c\n" +
            "90 7d d8 97 50 fa ec cd 25 c4 71 04 9d 84 c2 4f\n" +
            "a6 90 25 ec 33 65 54 27 58 a0 c1 48 74 7c 04 40\n" +
            "35 37 4b 37 b9 0e f0 e0 29 75 67 11 cc 22 26 1b\n" +
            "d4 20 be 55 67 21 c9 b9 db f9 e7 5f 14 cb 3a 30\n" +
            "3d 04 02 37 61 a1 fc 43 7a 7b 98 3f b3 6d c6 88\n" +
            "35 e7 62 b5 8e ba e8 03 20 fc f9 18 d6 26 8a 11\n" +
            "7b b1 47 05 47 3b 83 d4 6f 8e bc 34 75 76 a0 33\n" +
            "46 55 fd 16 2b 79 99 78 91 93 4c 85 1e b4 c4 50\n" +
            "f1 cf c3 50 0a 8b b6 9c ce 59 37 5a fb 11 3e 15\n" +
            "44 93 c1 3f 21 68 ed ab d7 10 92 67 9d 29 64 4c\n" +
            "1f 2c 3e b2 00 1a 83 52 d9 56 6d 9a ff 66 af a6\n" +
            "62 00 84 e1 68 67 94 e0 d4 ea a7 12 ac a2 60 c7\n" +
            "04 55 20 42 9d 37 7e 3c dd 3b 24 ba c1 33 d0 b2\n" +
            "bc 71 90 97 8b 2e c4 cc 3f 84 98 e0 05 8e 03 7c\n" +
            "3c 60 2d 9a ac 2f 71 13 97 b6 2f 0e ef ee eb 60\n" +
            "e8 a7 b6 51 fb 5c bb da e0 6b e6 63 d3 e7 e8 2b\n" +
            "e1 ff ac 1b 67 18 29 8b 3a 3e 39 2d 8d e3 41 e8\n" +
            "d1 83 4b d2 22 b2 f6 49 99 9b 7d 93 ab 75 89 c2\n" +
            "8c 05 d7 d8 c3 b6 8e 52 75 08 cf e5 74 aa 0f a5\n" +
            "26 9d 3a 3c 0c 86 d5 3f 63 67 43 66 12 a6 23 7f\n" +
            "44 99 ee 58 8a 56 b0 cf c7 66 d1 42 8b 6e 42 07\n" +
            "93 16 c7 0f 77 1a 76 8d f1 f0 b3 24 92 a1 59 fb\n" +
            "58 07 8c d3 96 6c 32 a8 da 26 af 6d 15 7f 21 14\n" +
            "8c 7e d9 82 92 fa 13 66 a6 11 d6 0f b9 b6 d5 83\n" +
            "f2 83 77 b8 c2 fe f5 ee a9 cb dc 0f d4 ef 98 e0\n");

    public static final byte[] clientAllHandshakeMessage = HexUtils.fromHexString(
                    "01 00 00 4a 03 03 5c 48 6a 33 93\n" +
                    "14 eb 56 d2 7d 86 07 56 83 80 95 ff 1e 3c 32 b4\n" +
                    "21 d0 70 ab e2 fb a0 6a b2 6a 3f 00 00 02 00 3c\n" +
                    "01 00 00 1f 00 0d 00 16 00 14 06 03 06 01 05 03\n" +
                    "05 01 04 03 04 01 04 02 02 03 02 01 02 02 ff 01\n" +
                    "00 01 00\n" +

                            "02 00 00 4d 03 03 5c 48 6a 36 a6 57 51 c6 13 a2\n" +
                            "88 df 39 a0 42 02 9c 7b 35 cb 4f 55 5d 91 3c 7f\n" +
                            "89 e2 c6 21 e2 eb 20 5c 48 6a 36 14 88 53 20 1e\n" +
                            "0f ef 8a 7d 37 04 9e a6 7f 3c 41 1d 4e 32 fe f5\n" +
                            "1e 97 b9 f3 61 11 e5 00 3c 00 00 05 ff 01 00 01\n" +
                            "00" +

                            "0b 00 03 8f 00 03 8c 00 03 89 30 82 03 85 30 82\n" +
                            "02 6d a0 03 02 01 02 02 09 00 ad e0 51 8f d5 09\n" +
                            "f3 bc 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05\n" +
                            "00 30 58 31 0b 30 09 06 03 55 04 06 13 02 43 4e\n" +
                            "31 0b 30 09 06 03 55 04 08 0c 02 58 58 31 0b 30\n" +
                            "09 06 03 55 04 07 0c 02 58 58 31 1c 30 1a 06 03\n" +
                            "55 04 0a 0c 13 44 65 66 61 75 6c 74 20 43 6f 6d\n" +
                            "70 61 6e 79 20 4c 74 64 31 11 30 0f 06 03 55 04\n" +
                            "03 0c 08 74 65 73 74 2e 63 6f 6d 30 20 17 0d 31\n" +
                            "39 30 31 32 33 30 31 34 37 32 31 5a 18 0f 32 31\n" +
                            "31 38 31 32 33 30 30 31 34 37 32 31 5a 30 58 31\n" +
                            "0b 30 09 06 03 55 04 06 13 02 43 4e 31 0b 30 09\n" +
                            "06 03 55 04 08 0c 02 58 58 31 0b 30 09 06 03 55\n" +
                            "04 07 0c 02 58 58 31 1c 30 1a 06 03 55 04 0a 0c\n" +
                            "13 44 65 66 61 75 6c 74 20 43 6f 6d 70 61 6e 79\n" +
                            "20 4c 74 64 31 11 30 0f 06 03 55 04 03 0c 08 74\n" +
                            "65 73 74 2e 63 6f 6d 30 82 01 22 30 0d 06 09 2a\n" +
                            "86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30\n" +
                            "82 01 0a 02 82 01 01 00 cd 79 c6 0c 71 f8 c0 34\n" +
                            "c1 c7 a9 1a f5 9a 96 42 54 e1 5b ad 10 c0 51 76\n" +
                            "7d 91 2b de 0b 8f af 61 2d 6d 28 44 2e 35 71 65\n" +
                            "20 3b 3c b9 07 c1 4d a3 c8 c6 13 f9 00 3e 95 c2\n" +
                            "56 55 3b 8c d8 b8 65 82 73 00 dc 7a f5 13 bf 74\n" +
                            "f2 82 71 85 66 fd bc 34 23 43 04 a0 4f d7 bc 96\n" +
                            "54 88 c2 91 de b3 a4 04 13 83 6c 27 a0 d8 52 d5\n" +
                            "b1 48 dd e9 07 a3 9c f2 51 dc 0e e2 72 ac 38 85\n" +
                            "3d 9b 76 34 0c 02 b3 86 bb 06 6d 8e f0 d2 1f 09\n" +
                            "56 db d8 b4 2f 70 76 30 34 97 b0 0e 83 03 59 58\n" +
                            "62 bb 4d 5e 1b 75 de d5 f9 5a be 65 25 92 d7 07\n" +
                            "8d 3c d2 cb 7e 46 06 27 51 59 6d 7c 3c 00 fb 3d\n" +
                            "fa 9e 99 91 cd 49 cf ce 11 d7 be 06 3e 18 50 48\n" +
                            "19 d6 0d a3 55 06 97 a1 a6 fa 2c 55 7b ba 91 18\n" +
                            "7d 75 74 9c d0 c8 a5 8c 00 af f3 04 ae d7 87 d1\n" +
                            "32 3c 07 cd f1 3f cc 1d 38 88 33 82 da d3 29 f8\n" +
                            "f0 c8 68 c9 8a 63 21 eb 02 03 01 00 01 a3 50 30\n" +
                            "4e 30 1d 06 03 55 1d 0e 04 16 04 14 92 a1 d9 27\n" +
                            "21 65 2a bc da fd c7 9d ef 5c 5a 70 40 04 1d 98\n" +
                            "30 1f 06 03 55 1d 23 04 18 30 16 80 14 92 a1 d9\n" +
                            "27 21 65 2a bc da fd c7 9d ef 5c 5a 70 40 04 1d\n" +
                            "98 30 0c 06 03 55 1d 13 04 05 30 03 01 01 ff 30\n" +
                            "0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82\n" +
                            "01 01 00 25 6b d1 da 31 63 ba 8c 71 dd 28 46 5a\n" +
                            "19 63 8d 03 d0 0f 97 12 4f 95 21 3d d6 a3 90 14\n" +
                            "58 56 b9 79 cd a6 6a b8 ec ab 43 d8 60 db cc 4e\n" +
                            "ea 1e f4 09 3d 2c 61 59 89 ed 5b b7 01 a0 f0 4c\n" +
                            "fe c4 d6 fc 09 8e 86 dd 88 3d ae 60 61 95 5b 04\n" +
                            "93 1b c7 b8 44 8a 2b 86 9f 91 6f e3 54 41 7b 3a\n" +
                            "31 46 17 48 65 8d af 94 23 50 bc 76 a8 05 73 3c\n" +
                            "68 37 c8 19 a3 8a 33 43 cd 08 f6 7e 28 33 d8 0e\n" +
                            "e9 9f 72 f6 5f c8 fe e9 fd 32 6a d1 99 21 24 aa\n" +
                            "87 db 49 a2 48 2c cb b6 b7 db 22 67 8f e9 5f 6a\n" +
                            "dc 90 e0 ad 02 da ef e1 a5 56 58 32 e4 90 33 78\n" +
                            "bb b6 29 d3 17 6a f6 b8 c0 d4 0c c4 03 cb 94 64\n" +
                            "02 34 e3 7d f2 c6 75 1c 52 3d bd 02 bb 27 5d 4e\n" +
                            "57 f1 bc fa d9 57 45 e3 4c 2b 3c 65 fd f8 7e bb\n" +
                            "2f ea 61 a0 d2 9b 71 bf 7b 3e 70 81 d8 f3 86 d1\n" +
                            "c1 0a e2 8d 73 4c ec f9 ec ef 5f 19 ef 51 da 1a\n" +
                            "9a e3 53\n" +
                            "\n" +
                            "\n" +
                            "\n" +
                            "\n" +
                            "0e 00 00 00\n" +


                    "10 00 01 02 01 00 69 8d 0e 95 67\n" +
                    "40 6b ae 0f cb 7e c1 59 34 c4 93 ba a1 ae bb 64\n" +
                    "e7 84 e3 54 bc 1e ed 9c 8a 96 7a f1 51 58 56 28\n" +
                    "9b 1a a8 fa a2 e5 0b 2c 0c 20 36 37 55 9c 9d 5f\n" +
                    "1a 76 19 18 6e 65 f0 e5 88 19 99 04 b4 49 31 af\n" +
                    "ce 30 08 22 f5 89 ed cf 32 5b 01 32 b8 76 7e 0d\n" +
                    "27 98 f2 df 7e 6c 88 5f 96 14 fd 4d ff e5 b6 0d\n" +
                    "50 da e6 72 f3 c9 18 52 10 e8 d9 c8 c6 78 03 b6\n" +
                    "bf 07 11 60 95 14 77 34 6d c0 c9 4c 5d 4c 25 25\n" +
                    "78 68 70 62 3f a9 21 35 f5 f0 46 34 21 3a e0 63\n" +
                    "56 a0 84 64 e5 9e d4 b9 fe 1a c4 d4 6d 31 70 4f\n" +
                    "da ae c5 ee 70 62 db 16 00 b7 f4 c0 3b ce ad 44\n" +
                    "fd a6 1a eb 7f 8b 1c 03 91 47 b9 15 69 5e 70 e8\n" +
                    "6b d1 82 ae d8 b6 76 c3 c5 ba 56 e2 87 ee bc 73\n" +
                    "c4 3c 7a 67 8a 2f 14 e4 ea d4 67 73 8b ea 9a 7c\n" +
                    "fb ac e4 a3 d9 cf 4e 81 ba b4 0c 2d 87 02 fa 82\n" +
                    "f6 f3 53 b6 f6 45 26 26 1a 1d 02\n"

    );



    /** 解密premaster, 最后48个字节才是pre-master, 最开始两字节为0x03 0x03 */
    public static byte[] decryptPreMaster(){
        BigInteger premaster = new BigInteger(clientEncryptedPreMaster);
        byte[] out = premaster.modPow(MyRSAInfo.d, MyRSAInfo.n).toByteArray();
        return Arrays.copyOfRange(out, out.length-48, out.length);
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
        byte[] premaster = decryptPreMaster();
        logger.info("decrypted pre master: \r\n{}", HexUtils.dumpString(premaster, 16));
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
            byte[] computedClientEncryptedHandshake = PRF(masterSecret, "client finished".getBytes(),
                    DigestUtil.sha256(clientAllHandshakeMessage), 12);
            logger.info("encrypted handshake: \r\n{}",
                    HexUtils.dumpString(computedClientEncryptedHandshake, 16));
        }
        {
            byte[] mac = DigestUtil.hmacsha256(HexUtils.join(
                    new byte[]{0,0,0,0,0,0,0,0, 22, 3, 3, 0, 16},
                    HexUtils.fromHexString("14 00 00 0c cc 4d 39 01 b6 55 af cd 8d b7 e5 c3")
                    ),
                    clientMacKey);
            logger.info("clientEncryptedHandshake mac: \r\n{}", HexUtils.dumpString(mac, 16));
        }

        /** 解密 clientEncryptedHandshake */
        {
            byte[] iv = Arrays.copyOf(clientEncryptedHandShakeMessage, 16);
            byte[] content = Arrays.copyOfRange(clientEncryptedHandShakeMessage, 16, clientEncryptedHandShakeMessage.length);
            byte[] decrypted = CipherUtil.cbcDecrypt(clientAESKey, iv, content);
            logger.info("decrypted handshake msg: \r\n{}", HexUtils.dumpString(decrypted, 16));
        }


        {
            byte[] iv = Arrays.copyOf(clientEncryptedAppData, 16);
            byte[] content = Arrays.copyOfRange(clientEncryptedAppData, 16, clientEncryptedAppData.length);
            byte[] decrypted = CipherUtil.cbcDecrypt(clientAESKey, iv, content);
            logger.info("decrypted application msg: \r\n{}", HexUtils.dumpString(decrypted, 16));
            logger.info("decrypted: \r\n{}", new String(decrypted));
        }
    }
}
