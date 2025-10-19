package org.massine.auth.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PemUtils {

    public static PublicKey parseRSAPublicKey(String pem) throws Exception {
        String s = pem.replaceAll("\\r?\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] der = Base64.getDecoder().decode(s);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    public static PrivateKey parseRSAPrivateKey(String pem) throws Exception {
        String s = pem.replaceAll("\\r?\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] der = Base64.getDecoder().decode(s);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    public static String toPem(String type, byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der).replaceAll("(.{64})", "$1\n");
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----";
    }
}
