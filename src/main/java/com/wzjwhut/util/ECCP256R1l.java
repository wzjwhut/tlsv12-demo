package com.wzjwhut.util;

import com.wzjwhut.example.Analyse_DHE_RSA_WITH_AES_128_CBC_SHA256;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

/** 椭圆加密算法辅助类

*/
public class ECCP256R1l {
    private final static Logger logger = LogManager.getLogger(ECCP256R1l.class);

    /** 构造secp256r1曲线, 系统有现成的接口. 这里只是为了演示
     * http://www.secg.org/sec2-v2.pdf
     * */

    /** jdk自带的接口,开放的功能太少了. 换成开源的 */
//    BigInteger p = new BigInteger("00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
//    BigInteger a = new BigInteger("00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
//    BigInteger b = new BigInteger("005AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
//    BigInteger seed = new BigInteger("00C49D360886E704936A6678E1139D26B7819F7E90", 16);
//    BigInteger G_x = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
//    BigInteger G_y = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
//    BigInteger n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
//    BigInteger h = BigInteger.valueOf(1L);
//    ECFieldFp ecFieldFp = new ECFieldFp(p);
//    EllipticCurve ec = new EllipticCurve(ecFieldFp, a, b, seed.toByteArray());

    static ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    static org.bouncycastle.math.ec.ECCurve bcCurve = spec.getCurve();

    public static byte[] multi(BigInteger pointX, BigInteger pointY, BigInteger k){
        ECPoint point = bcCurve.createPoint(pointX, pointY, false);
        point = point.multiply(k);
        return point.getX().toBigInteger().toByteArray();
    }
}
