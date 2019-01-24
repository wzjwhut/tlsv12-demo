package com.wzjwhut.example;

import com.wzjwhut.util.DigestUtil;
import com.wzjwhut.util.HexUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class PBKDF2 {
    private final static Logger logger = LogManager.getLogger(PBKDF2.class);

    public static byte[] df2(byte[] p /** password */, byte[] s /** salt */,
                      int c /** iteration count */, int dkLen) throws Throwable{
        /** 使用HMAC-SHA1算法 */
        logger.info("password size: {}", p.length);
        logger.info("salt size: {}", s.length);
        logger.info("count size: {}", c);
        logger.info("dkLen size: {}", dkLen);
        int hLen = 20;
        int l = (dkLen + hLen -1)/hLen;
        int r = dkLen - (l - 1) * hLen;
        byte[][] T = new byte[l][20];
        for(int i=0; i<l; i++){
            T[i] = F(p, s, c, i+1);
        }
        return Arrays.copyOf(HexUtils.join(T), dkLen);
    }

    public static byte[] F(byte[] p, byte[] s, int c, int i) throws Throwable{
        int length = s.length;
        s = Arrays.copyOf(s, s.length + 4);
        s[length] = (byte)(i>>24);
        s[length+1] = (byte)(i>>16);
        s[length+2] = (byte)(i>>8);
        s[length+3] = (byte)(i>>0);
        byte[] preU = DigestUtil.hmacsha1(s, p); /** 注意参数的先后顺序 */
        byte[] out = Arrays.copyOf(preU, preU.length);
        for(int x=1; x<c; x++){
            byte[] u = DigestUtil.hmacsha1(preU, p);
            xor(out, u);
            preU = u;
        }
        return out;
    }

    private static void xor(byte[] x, byte[] y){
        for(int i=0; i<x.length; i++){
            x[i] = (byte)(x[i]^y[i]);
        }
    }

    /** 使用jdk自带的解密算法 */
    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws Throwable {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }
}
