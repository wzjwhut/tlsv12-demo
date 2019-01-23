package com.wzjwhut.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServerSSLContextFactory {

    private final static Logger logger = LogManager.getLogger(ServerSSLContextFactory.class);

    private final static String[] _excludeCipherSuites = { "TLS_DHE_.*", "TLS_ECDHE_.*", "TLS_ECDH_.*" };
    private String[] _selectedCipherSuites;

    private URL _pfxUrl;
    private String _pfxPassword;

    private String _pfxType;
    private SSLContext _context;
    private String name = "";

    public ServerSSLContextFactory(URL clientUrl, String clientPass) {
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        String type = "JKS";
        this._pfxType = type;
        this._pfxUrl = clientUrl;
        this._pfxPassword = clientPass;
    }

    private void removeComplicateSuite(SSLContext context) {
        SSLParameters enabled = context.getDefaultSSLParameters();
        SSLParameters supported = context.getSupportedSSLParameters();
        selectCipherSuites(enabled.getCipherSuites(), supported.getCipherSuites());
    }

    private void selectCipherSuites(String[] enabledCipherSuites, String[] supportedCipherSuites) {
        List<String> selected_ciphers = new ArrayList<>();
        selected_ciphers.addAll(Arrays.asList(enabledCipherSuites));

        for (String excludeCipherSuite : _excludeCipherSuites) {
            Pattern excludeCipherPattern = Pattern.compile(excludeCipherSuite);
            for (Iterator<String> i = selected_ciphers.iterator(); i.hasNext();) {
                String selectedCipherSuite = i.next();
                Matcher m = excludeCipherPattern.matcher(selectedCipherSuite);
                if (m.matches())
                    i.remove();
            }
        }
        _selectedCipherSuites = selected_ciphers.toArray(new String[0]);
        for (String suite : _selectedCipherSuites) {
            logger.info("selected cihper suite: {}", suite);
        }
    }

    public void customize(SSLContext sslContext, SSLEngine engine) {
        // 移除过于复杂的加密算法
        logger.info("set cipher suites");
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setCipherSuites(_selectedCipherSuites);
        engine.setSSLParameters(parameters);
    }

    public SSLContext newContext() throws Exception {
        logger.info("create new ssl context");
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore tks = KeyStore.getInstance("JKS");

            ks.load(_pfxUrl.openStream(), _pfxPassword.toCharArray());
            kmf.init(ks, _pfxPassword.toCharArray());
            tks.load(_pfxUrl.openStream(), _pfxPassword.toCharArray());
            tmf.init(tks);
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;
        } catch (Exception ex) {
            logger.error("create ssl context failed", ex);
            return null;
        }
    }
}
