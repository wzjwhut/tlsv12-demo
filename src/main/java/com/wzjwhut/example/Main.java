package com.wzjwhut.example;

import com.wzjwhut.util.HexUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.nio.charset.StandardCharsets;

public class Main {
    private final static Logger logger = LogManager.getLogger(Main.class);

    private final static byte[] rawMessage = "hello world".getBytes();

    private static String createRequest(String host){
        return   String.format("GET https://%s/ HTTP/1.1\r\n" +
                "Host: %s\r\n" +
                "Accept: text/html\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Connection: keep-alive\r\n" +
                "Upgrade-Insecure-Requests: 1\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n", host, host);
    }

    public static void main(String[] args) throws Throwable {
        //String s = "0xab, 0xcd, ef\r\na,b";
        //logger.info("\r\n{}", HexUtils.dumpString(MyRSAInfo.d.toByteArray(), 16));
        pcap(null);
    }

    /** 使用指定的握手协议来抓包, 服务器是自建的, 因为百度不支持不太安全的加密算法 */
    public static void pcap(String[] args) throws Throwable {
        ClientSSLContextFactory clientSSLContextFactory = new ClientSSLContextFactory();
        SSLContext clientContext = clientSSLContextFactory.newContext();
        SSLSocketFactory socketFactory = clientContext.getSocketFactory();

        String[] defaultCiphers = socketFactory.getDefaultCipherSuites();
        logger.info("default ciphers: {}", StringUtils.join(defaultCiphers, "\r\n"));

        String host = "115.28.94.100";
        //String host = "www.baidu.com";
        SSLSocket socket = (SSLSocket) socketFactory.createSocket(host, 443);
        socket.setNeedClientAuth(true);
        socket.setEnabledCipherSuites(new String[]{
                /** 最简单的方式 */
                //"TLS_RSA_WITH_AES_128_CBC_SHA256",

                /** 支持前向安全特性 */
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        });
        socket.getOutputStream().write(createRequest(host).getBytes());
        byte[] resp = new byte[4096];
        int n = socket.getInputStream().read(resp);
        logger.info("{}", new String(resp,0, n, StandardCharsets.UTF_8));
        socket.close();
        LogManager.shutdown();
    }
}
