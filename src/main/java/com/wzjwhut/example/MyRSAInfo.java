package com.wzjwhut.example;

import com.wzjwhut.util.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Random;

/** 帮助分析抓包到的数据, 使用已知的证书/公钥/私钥 来分析握手过程
 *  私钥和公钥. 格式
 *  https://blog.csdn.net/wzj_whut/article/details/86477568
 * */
public class MyRSAInfo {
    private final static Logger logger = LogManager.getLogger(MyRSAInfo.class);
    public final static String myEncryptedKeyFile =
            "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIff/B18M9S1UCAggA" +
            "MBQGCCqGSIb3DQMHBAjWzSQ2EWm5dgSCBMhhZd6XfsW6Rcbwn0/V5NhSUQ/UoQ6n" +
            "y7nE8ozDlWlWb2at6eXCfjsVkWHxkeCEI09qEmfEAt1u+qgwtRBYfkcaWDUgbmR5" +
            "13lGezZwHXbi0iIQetkgS/zcAOdeRuGQancdBOW1Z58OOpyriWVM2fZRUm1UyIj/" +
            "n3CJfhAZf/ClZ5xNEI6SUStw3goru4kfZ1c7fyrqorL9QKEUlgmfZ87YgyHFcJ/A" +
            "S7bKadWZA9BeknDottOcHmhKECWrd+oe4hgq8czZfwsFq6Fgdg1qwbhSUqObekhW" +
            "/aJ+lPAXR6k5kXYX1idEMuGDjrLxnJqit4C8a4K40OgagV6ph10Bn53tQFXV+L+q" +
            "gpyRdUPCXMxijTzEIdZj6dktymu8MlDODIC6BQ+jc/M5TrH/TyP/JJlAIPfO42In" +
            "ptIJrIZ5g+PYUvGgf2jYqaeN3ZKfOFgLCJRnyMZIv5EaNUGm4TdbyQiOSYprJu1u" +
            "NTjON7AM6zAmiHyI1096mDmjE7C9560Eza756B43hDnGzNH4O9MGpLDYE7q6YS7f" +
            "HaP2rjY1FWwHfh8nPDMQfw6AP7jH1vwEKJPnDpIYkX5T5GHVe7wPw6EUEglGrehN" +
            "5EZzqDuQsL+l8p51Lpi7Dcm1PWWmz3CAFrkqk8Y2oLLE2yoVCTYPiye02yPrCEuj" +
            "qtW8QA5/08T43dHON3f1mCmhL60JSIie1QFiGSq5JAHA1zpEOR2GZbTbgr1quNad" +
            "1twTw0AMXdHUOoku4VWv4eNIgXep2W7lxdueWjOBTbsDI2oYbYKnGElpUWuDhF4E" +
            "pFuJmj72Xczfsp4MKoLiAjgeOMREy7F5XRpoTKB9yRgU0iaDFTS9JkzPhjm+dbsd" +
            "GxtaqxDhe4MTVMQsdhjxo8P5+dvU4G0F0rHu0wnVnXbyB3x5EDoEu1l/yPD5Q56t" +
            "IwscRggVyZLxu+PlrKWp7y7HkITfPXFNCJb5m6JZZ+1ZYbjvZEzI5Mc5IEpU9/lg" +
            "dvFPClYCVxX425jKNsr1pKQFrcn8Byyij0d5SIA6J+H/Z67IQnfnHnqLR/zaRkgp" +
            "yYJMPNKVma/vwinbRx/CTXi9s9UBJmOu1l2lppHnkH2gs33yk0p4CjHJEQkmp1kJ" +
            "Qdd2Gbb7tP2HiPSx9nOcBBpMbhlK607QYfXmfmlRlGJpanixk7eoYLXnxF3PCwxw" +
            "7q5cOq5LuayMuq2xeRplp7TZR8jnup0AlUbxl0q8AkjIwBjL5aZctFh9fhckt8RJ" +
            "ldsKxN45kb/+dcx16XgQq0fou25ZJMWVoIoiLdSp33Q9GmaA73lZl9LQ/VlwfFX+" +
            "3Npna1k95zJ9SM8l6rDJr5XsHTVFt8ixjr2OfoZ5t3aTbBfKxToqczGUHzBhW6Fj" +
            "YHU+6N/RVGHLT6gH8G2EPnSgh+t05pI30uFZPB3/SqlDmQ6y2tFTpYISkWKv0CKd" +
            "hf46zUYsR+zr5jRSYN/gOvxau9cxvaRkvMxE1S8+qRSPtAGCz4t8foIEWansI8wJ" +
            "Tm7g/iVkn2F8zmXpJVtqB+ACz/jvcRS6yncMAWQ7+KMAG8f4kuV0x0WW/0TPyeDb" +
            "HfCzq5Bs1VcqTljreEzVQtGgu3XnhL4wITZ3iWh4rvhgVL+XeyR1na1gVn60ESKz" +
            "Z9E=";

    public final static byte[] myPrivateKey = HexUtils.fromHexString(
            "61 65 de 97 7e c5\n" +
            "ba 45 c6 f0 9f 4f d5 e4 d8 52 51 0f d4 a1 0e a7\n" +
            "cb b9 c4 f2 8c c3 95 69 56 6f 66 ad e9 e5 c2 7e\n" +
            "3b 15 91 61 f1 91 e0 84 23 4f 6a 12 67 c4 02 dd\n" +
            "6e fa a8 30 b5 10 58 7e 47 1a 58 35 20 6e 64 79\n" +
            "d7 79 46 7b 36 70 1d 76 e2 d2 22 10 7a d9 20 4b\n" +
            "fc dc 00 e7 5e 46 e1 90 6a 77 1d 04 e5 b5 67 9f\n" +
            "0e 3a 9c ab 89 65 4c d9 f6 51 52 6d 54 c8 88 ff\n" +
            "9f 70 89 7e 10 19 7f f0 a5 67 9c 4d 10 8e 92 51\n" +
            "2b 70 de 0a 2b bb 89 1f 67 57 3b 7f 2a ea a2 b2\n" +
            "fd 40 a1 14 96 09 9f 67 ce d8 83 21 c5 70 9f c0\n" +
            "4b b6 ca 69 d5 99 03 d0 5e 92 70 e8 b6 d3 9c 1e\n" +
            "68 4a 10 25 ab 77 ea 1e e2 18 2a f1 cc d9 7f 0b\n" +
            "05 ab a1 60 76 0d 6a c1 b8 52 52 a3 9b 7a 48 56\n" +
            "fd a2 7e 94 f0 17 47 a9 39 91 76 17 d6 27 44 32\n" +
            "e1 83 8e b2 f1 9c 9a a2 b7 80 bc 6b 82 b8 d0 e8\n" +
            "1a 81 5e a9 87 5d 01 9f 9d ed 40 55 d5 f8 bf aa\n" +
            "82 9c 91 75 43 c2 5c cc 62 8d 3c c4 21 d6 63 e9\n" +
            "d9 2d ca 6b bc 32 50 ce 0c 80 ba 05 0f a3 73 f3\n" +
            "39 4e b1 ff 4f 23 ff 24 99 40 20 f7 ce e3 62 27\n" +
            "a6 d2 09 ac 86 79 83 e3 d8 52 f1 a0 7f 68 d8 a9\n" +
            "a7 8d dd 92 9f 38 58 0b 08 94 67 c8 c6 48 bf 91\n" +
            "1a 35 41 a6 e1 37 5b c9 08 8e 49 8a 6b 26 ed 6e\n" +
            "35 38 ce 37 b0 0c eb 30 26 88 7c 88 d7 4f 7a 98\n" +
            "39 a3 13 b0 bd e7 ad 04 cd ae f9 e8 1e 37 84 39\n" +
            "c6 cc d1 f8 3b d3 06 a4 b0 d8 13 ba ba 61 2e df\n" +
            "1d a3 f6 ae 36 35 15 6c 07 7e 1f 27 3c 33 10 7f\n" +
            "0e 80 3f b8 c7 d6 fc 04 28 93 e7 0e 92 18 91 7e\n" +
            "53 e4 61 d5 7b bc 0f c3 a1 14 12 09 46 ad e8 4d\n" +
            "e4 46 73 a8 3b 90 b0 bf a5 f2 9e 75 2e 98 bb 0d\n" +
            "c9 b5 3d 65 a6 cf 70 80 16 b9 2a 93 c6 36 a0 b2\n" +
            "c4 db 2a 15 09 36 0f 8b 27 b4 db 23 eb 08 4b a3\n" +
            "aa d5 bc 40 0e 7f d3 c4 f8 dd d1 ce 37 77 f5 98\n" +
            "29 a1 2f ad 09 48 88 9e d5 01 62 19 2a b9 24 01\n" +
            "c0 d7 3a 44 39 1d 86 65 b4 db 82 bd 6a b8 d6 9d\n" +
            "d6 dc 13 c3 40 0c 5d d1 d4 3a 89 2e e1 55 af e1\n" +
            "e3 48 81 77 a9 d9 6e e5 c5 db 9e 5a 33 81 4d bb\n" +
            "03 23 6a 18 6d 82 a7 18 49 69 51 6b 83 84 5e 04\n" +
            "a4 5b 89 9a 3e f6 5d cc df b2 9e 0c 2a 82 e2 02\n" +
            "38 1e 38 c4 44 cb b1 79 5d 1a 68 4c a0 7d c9 18\n" +
            "14 d2 26 83 15 34 bd 26 4c cf 86 39 be 75 bb 1d\n" +
            "1b 1b 5a ab 10 e1 7b 83 13 54 c4 2c 76 18 f1 a3\n" +
            "c3 f9 f9 db d4 e0 6d 05 d2 b1 ee d3 09 d5 9d 76\n" +
            "f2 07 7c 79 10 3a 04 bb 59 7f c8 f0 f9 43 9e ad\n" +
            "23 0b 1c 46 08 15 c9 92 f1 bb e3 e5 ac a5 a9 ef\n" +
            "2e c7 90 84 df 3d 71 4d 08 96 f9 9b a2 59 67 ed\n" +
            "59 61 b8 ef 64 4c c8 e4 c7 39 20 4a 54 f7 f9 60\n" +
            "76 f1 4f 0a 56 02 57 15 f8 db 98 ca 36 ca f5 a4\n" +
            "a4 05 ad c9 fc 07 2c a2 8f 47 79 48 80 3a 27 e1\n" +
            "ff 67 ae c8 42 77 e7 1e 7a 8b 47 fc da 46 48 29\n" +
            "c9 82 4c 3c d2 95 99 af ef c2 29 db 47 1f c2 4d\n" +
            "78 bd b3 d5 01 26 63 ae d6 5d a5 a6 91 e7 90 7d\n" +
            "a0 b3 7d f2 93 4a 78 0a 31 c9 11 09 26 a7 59 09\n" +
            "41 d7 76 19 b6 fb b4 fd 87 88 f4 b1 f6 73 9c 04\n" +
            "1a 4c 6e 19 4a eb 4e d0 61 f5 e6 7e 69 51 94 62\n" +
            "69 6a 78 b1 93 b7 a8 60 b5 e7 c4 5d cf 0b 0c 70\n" +
            "ee ae 5c 3a ae 4b b9 ac 8c ba ad b1 79 1a 65 a7\n" +
            "b4 d9 47 c8 e7 ba 9d 00 95 46 f1 97 4a bc 02 48\n" +
            "c8 c0 18 cb e5 a6 5c b4 58 7d 7e 17 24 b7 c4 49\n" +
            "95 db 0a c4 de 39 91 bf fe 75 cc 75 e9 78 10 ab\n" +
            "47 e8 bb 6e 59 24 c5 95 a0 8a 22 2d d4 a9 df 74\n" +
            "3d 1a 66 80 ef 79 59 97 d2 d0 fd 59 70 7c 55 fe\n" +
            "dc da 67 6b 59 3d e7 32 7d 48 cf 25 ea b0 c9 af\n" +
            "95 ec 1d 35 45 b7 c8 b1 8e bd 8e 7e 86 79 b7 76\n" +
            "93 6c 17 ca c5 3a 2a 73 31 94 1f 30 61 5b a1 63\n" +
            "60 75 3e e8 df d1 54 61 cb 4f a8 07 f0 6d 84 3e\n" +
            "74 a0 87 eb 74 e6 92 37 d2 e1 59 3c 1d ff 4a a9\n" +
            "43 99 0e b2 da d1 53 a5 82 12 91 62 af d0 22 9d\n" +
            "85 fe 3a cd 46 2c 47 ec eb e6 34 52 60 df e0 3a\n" +
            "fc 5a bb d7 31 bd a4 64 bc cc 44 d5 2f 3e a9 14\n" +
            "8f b4 01 82 cf 8b 7c 7e 82 04 59 a9 ec 23 cc 09\n" +
            "4e 6e e0 fe 25 64 9f 61 7c ce 65 e9 25 5b 6a 07\n" +
            "e0 02 cf f8 ef 71 14 ba ca 77 0c 01 64 3b f8 a3\n" +
            "00 1b c7 f8 92 e5 74 c7 45 96 ff 44 cf c9 e0 db\n" +
            "1d f0 b3 ab 90 6c d5 57 2a 4e 58 eb 78 4c d5 42\n" +
            "d1 a0 bb 75 e7 84 be 30 21 36 77 89 68 78 ae f8\n" +
            "60 54 bf 97 7b 24 75 9d ad 60 56 7e b4 11 22 b3\n" +
            "67 d1");

    //由私钥解密出来的RSA参数为
    public static final BigInteger n = new BigInteger(HexUtils.fromHexString(
            "00 cd 79 c6 0c 71 f8 c0 34 c1 c7\n" +
            "a9 1a f5 9a 96 42 54 e1 5b ad 10 c0 51 76 7d 91\n" +
            "2b de 0b 8f af 61 2d 6d 28 44 2e 35 71 65 20 3b\n" +
            "3c b9 07 c1 4d a3 c8 c6 13 f9 00 3e 95 c2 56 55\n" +
            "3b 8c d8 b8 65 82 73 00 dc 7a f5 13 bf 74 f2 82\n" +
            "71 85 66 fd bc 34 23 43 04 a0 4f d7 bc 96 54 88\n" +
            "c2 91 de b3 a4 04 13 83 6c 27 a0 d8 52 d5 b1 48\n" +
            "dd e9 07 a3 9c f2 51 dc 0e e2 72 ac 38 85 3d 9b\n" +
            "76 34 0c 02 b3 86 bb 06 6d 8e f0 d2 1f 09 56 db\n" +
            "d8 b4 2f 70 76 30 34 97 b0 0e 83 03 59 58 62 bb\n" +
            "4d 5e 1b 75 de d5 f9 5a be 65 25 92 d7 07 8d 3c\n" +
            "d2 cb 7e 46 06 27 51 59 6d 7c 3c 00 fb 3d fa 9e\n" +
            "99 91 cd 49 cf ce 11 d7 be 06 3e 18 50 48 19 d6\n" +
            "0d a3 55 06 97 a1 a6 fa 2c 55 7b ba 91 18 7d 75\n" +
            "74 9c d0 c8 a5 8c 00 af f3 04 ae d7 87 d1 32 3c\n" +
            "07 cd f1 3f cc 1d 38 88 33 82 da d3 29 f8 f0 c8\n" +
            "68 c9 8a 63 21 eb "));
    public static final BigInteger d = new BigInteger(HexUtils.fromHexString(
            "00 b9 82 a4 e5 1d 8d 08 f3 58 b4 cb 9f 54 78 d2 0a\n" +
            "67 19 e3 ac 17 c0 9a 8b d1 08 5d 43 a6 ca 7d fb\n" +
            "cd 88 8c df 29 9d 04 98 d9 85 c1 e8 07 f1 65 08\n" +
            "67 3f 36 4f 0c 02 75 31 34 c2 d4 f5 ef c0 63 9d\n" +
            "67 f9 32 16 2c e8 3c 65 f8 80 fe bf 03 62 38 26\n" +
            "16 63 ee 6c 52 49 a3 b1 51 f6 fb 3b b9 86 14 a1\n" +
            "bd 80 5d 08 56 36 98 6a e8 19 b2 88 2e 66 70 4f\n" +
            "72 ca ac 01 94 a8 9a 8a e9 39 4f 79 e4 12 18 43\n" +
            "fe 47 78 21 61 32 21 b2 e4 f9 7b a5 b4 4a 83 80\n" +
            "dc b1 f3 89 87 5b 7e 06 a5 d4 88 af 95 46 fb 85\n" +
            "21 fc ba 01 f0 83 1e 27 4c ba b8 57 0b a5 ec b8\n" +
            "7b 5e 56 c7 2f 4c 64 24 c0 7b c0 51 d6 ba 58 15\n" +
            "83 19 26 12 8e b4 9b 4e 97 48 72 3f 1a ac 12 bd\n" +
            "5d 0b 18 90 01 e5 da c4 1f f2 2e 96 cb bb a5 46\n" +
            "bd 8c 7e cd b6 06 39 d2 fc ea 71 1a 76 45 dd 0b\n" +
            "2f 70 aa ab 0d b4 90 b1 6f e0 1c 92 8b 59 de 99"));
    public static final BigInteger e = BigInteger.valueOf(65537L);
    static {
        /** 我的私钥. 密码为123456 */
        //logger.info("server private key: \r\n{}", HexUtils.dumpString(Base64.getDecoder().decode(myEncryptedKeyFile), 16));
        //logger.info("d:\r\n{}", HexUtils.dumpString(d.toByteArray(), 16));
    }

    public static void decryptMyKey() throws Throwable{
        byte[] salt = new byte[]{
                0x7d , (byte) 0xff, (byte) 0xc1, (byte) 0xd7, (byte) 0xc3, 0x3d , 0x4b, 0x55,
        };
        byte[] password = "123456".getBytes();
        byte[] dk = PBKDF2.df2(password, salt, 2048, 24);
        byte[] dk2 = PBKDF2.pbkdf2("123456".toCharArray(), salt, 2048, 24);
        logger.info("dk = {}", dk);
        logger.info("dk2 = {}", HexUtils.dumpString(dk2));
        byte[] iv = new byte[]{
                (byte)0xd6 , (byte)0xcd , (byte)0x24 , (byte)0x36 ,
                (byte)0x11 , (byte)0x69 , (byte)0xb9 , (byte)0x76
        };
        logger.info("private key len: {}", myPrivateKey.length);
        byte[] out = DesUtil.decrypt_DES_EDE3_CBC(myPrivateKey, dk2, iv);
        logger.info("out = {}\r\n{}", out.length, HexUtils.dumpString(out, 16));
    }

    public static void main(String[] args){
        byte[] bytes = new byte[48];
        new Random().nextBytes(bytes);
        byte[] testData = {1, 2, 10, 7, 8};
        BigInteger out = new BigInteger(bytes).modPow(e, n);
        logger.info("input: {}", bytes);
        logger.info("out: {}", out);
        logger.info("decrypted: {}", out.modPow(d, n).toByteArray());
    }

}
