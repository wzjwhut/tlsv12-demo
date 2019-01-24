package com.wzjwhut.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

public class HexUtils {
    private final static Logger logger = LogManager.getLogger(HexUtils.class);

	private final static char[] chars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	public static String hexString(byte[] bin) {
		if(bin == null){
			return "";
		}
		StringBuilder stringBuf = new StringBuilder(bin.length<<1);
		for (int i = 0; i < bin.length; i++) {
			stringBuf.append(chars[(bin[i]>>4)&0x0f]);
			stringBuf.append(chars[bin[i]&0x0f]);
		}
		return stringBuf.toString();
	}


    public static String dumpString(byte[] bin) {
        if(bin == null){
            return "";
        }
        StringBuilder stringBuf = new StringBuilder(bin.length<<1);
        for (int i = 0; i < bin.length; i++) {
            stringBuf.append(chars[(bin[i]>>4)&0x0f]);
            stringBuf.append(chars[bin[i]&0x0f]);
            stringBuf.append(' ');
        }
        return stringBuf.toString();
    }

    public static String dumpString(byte[] bin, int numPerLine) {
        if(bin == null){
            return "";
        }
        StringBuilder stringBuf = new StringBuilder(bin.length<<1);
        for (int i = 0; i < bin.length; i++) {
            stringBuf.append(chars[(bin[i]>>4)&0x0f]);
            stringBuf.append(chars[bin[i]&0x0f]);
            if((i%numPerLine) == (numPerLine-1)){
                stringBuf.append("\r\n");
            }else {
                stringBuf.append(' ');
            }
        }
        return stringBuf.toString();
    }

	public static String hexString(byte[] bin, int offset, int len) {
		if(bin == null){
			return "";
		}
		StringBuilder stringBuf = new StringBuilder(bin.length<<1);
		for (int i = offset; i < offset + len; i++) {
			stringBuf.append(chars[(bin[i]>>4)&0x0f]);
			stringBuf.append(chars[bin[i]&0x0f]);
		}
		return stringBuf.toString();
	}

	public static StringBuilder hexString(StringBuilder builder, byte[] bin, int offset, int len){
        for (int i = offset; i < offset + len; i++) {
            builder.append(chars[(bin[i]>>4)&0x0f]);
            builder.append(chars[bin[i]&0x0f]);
        }
        return builder;
    }

    public static StringBuilder hexByte(StringBuilder builder, byte b){
        builder.append(chars[(b>>4)&0x0f]);
        builder.append(chars[b&0x0f]);
        return builder;
    }

    public static StringBuilder hex48(StringBuilder builder, long value){
        hex16(builder, (int) (value>>32));
        hex32(builder, (int)value);
        return builder;
    }

    public static StringBuilder hex32(StringBuilder builder, int value){
        builder.append(chars[(value>>28)&0x0f]);
        builder.append(chars[(value>>24)&0x0f]);
        builder.append(chars[(value>>20)&0x0f]);
        builder.append(chars[(value>>16)&0x0f]);
        builder.append(chars[(value>>12)&0x0f]);
        builder.append(chars[(value>>8)&0x0f]);
        builder.append(chars[(value>>4)&0x0f]);
        builder.append(chars[(value)&0x0f]);
        return builder;
    }

    public static StringBuilder hex24(StringBuilder builder, int value){
        builder.append(chars[(value>>20)&0x0f]);
        builder.append(chars[(value>>16)&0x0f]);
        builder.append(chars[(value>>12)&0x0f]);
        builder.append(chars[(value>>8)&0x0f]);
        builder.append(chars[(value>>4)&0x0f]);
        builder.append(chars[(value)&0x0f]);
        return builder;
    }
    public static StringBuilder hex16(StringBuilder builder, int value){
        builder.append(chars[(value>>12)&0x0f]);
        builder.append(chars[(value>>8)&0x0f]);
        builder.append(chars[(value>>4)&0x0f]);
        builder.append(chars[(value)&0x0f]);
        return builder;
    }

    public static StringBuilder hexShort(StringBuilder builder, short value){
	    byte high = (byte) (value>>8);
	    byte low = (byte)value;
        builder.append(chars[(high>>4)&0x0f]);
        builder.append(chars[high&0x0f]);
        builder.append(chars[(low>>4)&0x0f]);
        builder.append(chars[low&0x0f]);
        return builder;
    }


    public static String dumpString(byte[] bin, int offset, int len) {
        if(bin == null){
            return "";
        }
        StringBuilder stringBuf = new StringBuilder(bin.length<<1);
        for (int i = offset; i < offset + len; i++) {
            stringBuf.append(chars[(bin[i]>>4)&0x0f]);
            stringBuf.append(chars[bin[i]&0x0f]);
            stringBuf.append(' ');
        }
        return stringBuf.toString();
    }

    public static String dumpString(ByteBuffer buffer, int len){
        len = Math.min(len, buffer.remaining());
        int pos = buffer.position();
        byte[] content = new byte[len];
        buffer.get(content);
        buffer.position(pos);
        return dumpString(content);
    }

    public static byte[] join(byte[]... array){
        int len = 0;
        for(byte[] a : array){
            //logger.info("join: {}", a);
            len += a.length;
        }
        byte[] out = new byte[len];
        len = 0;
        for(byte[] a : array){
            System.arraycopy(a, 0, out, len, a.length);
            len += a.length;
        }
        return out;
    }

    /** */
    public static byte[] fromHexString(String hexString){
        String str = StringUtils.replaceAll(hexString, "[\t\r\n,]", " ");
        String[] splits = StringUtils.split(str);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        for(String s : splits){
            if(s.startsWith("0x") || s.startsWith("0X")){
                s = s.substring(2);
            }
            for(int i=0; i<s.length(); i+=2){
                if((i+1) <s.length()){
                    int c0 = hexCharToInt(s.charAt(i));
                    int c1 = hexCharToInt(s.charAt(i+1));
                    bout.write((c0<<4) | c1);
                }else{
                    bout.write(hexCharToInt(s.charAt(i)));
                }
            }
        }
        return bout.toByteArray();
    }

    public static int hexCharToInt(char c){
        if(c>='0' && c <='9'){
            return c - '0';
        }else if(c>='a' && c <='f'){
            return c -'a' + 10;
        }else if(c>='A' && c <='F'){
            return c -'A' + 10;
        }else{
            return 0;
        }
    }
}
