package com.wzjwhut.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class DesUtil {
    private final static Logger logger = LogManager.getLogger(DesUtil.class);
    public static byte[] encryptByKey(byte[] datasource, String key) {
        try{
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(key.getBytes());
            //创建一个密匙工厂，然后用它把DESKeySpec转换成
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(desKey);
            //Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DES/CBC");
            //用密匙初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, securekey, random);
            //现在，获取数据并加密
            //正式执行加密操作
            return cipher.doFinal(datasource);
        }catch(Throwable e){
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] src, String key) throws Exception {
        // 创建一个DESKeySpec对象
        DESKeySpec desKey = new DESKeySpec(key.getBytes());
        // 创建一个密匙工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        // 将DESKeySpec对象转换成SecretKey对象
        SecretKey securekey = keyFactory.generateSecret(desKey);
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance("DES");
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey);
        // 真正开始解密操作
        return cipher.doFinal(src);
    }

    private final static byte[][] PADDING_BYTES = {
            new byte[]{0x01},
            new byte[]{0x02, 0x02,},
            new byte[]{0x03, 0x03, 0x03,},
            new byte[]{0x04, 0x04, 0x04, 0x04,},
            new byte[]{0x05, 0x05, 0x05, 0x05, 0x05,},
            new byte[]{0x06, 0x06, 0x06, 0x06, 0x06, 0x06,},
            new byte[]{0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,},
            new byte[]{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08},
    };

//    private static byte[] paddingKey(byte[] key){
//        if(key.length == 24){
//            return key;
//        }else if(key.length<24){
//            byte[] newkey = Arrays.copyOf(key, 24);
//            byte[] padding =
//            System.arraycopy(PADDING_BYTES, 0, newkey, key.length, 24 - key.length);
//            logger.info("new key: {}", newkey);
//            return newkey;
//        }else{
//            return Arrays.copyOf(key, 24);
//        }
//    }

    public static byte[] encrypt_DES_EDE3_CBC(byte[] datasource, byte[] key, byte[] iv) throws Exception {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(new DESedeKeySpec(key));
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            return cipher.doFinal(datasource);
    }

    public static byte[] decrypt_DES_EDE3_CBC(byte[] src, byte[] key, byte[] iv) throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(new DESedeKeySpec(key));
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        return cipher.doFinal(src);
    }
}
