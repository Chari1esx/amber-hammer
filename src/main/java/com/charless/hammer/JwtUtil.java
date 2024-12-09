package com.charless.hammer;

import com.charless.amber.CharSeqHelper;
import com.charless.amber.DsGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

/**
 * 签发与解析 Java Web Token
 * { DsGenerator CharSeqHelper }
 * { jjwt-api jjwt-impl jjwt-jackson slf4j logback }
 */
public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    /**
     * Token 标准字段 -> 标识主体
     */
    private static final String subject = "Authentication";

    /**
     * Token 有效期 (秒)
     */
    private static final long expirationSeconds = 60 * 60;

    /**
     * Token 签名密钥 (字符串 长度必须为 32)
     */
    private static final String signKey = "custom-token-sign-key-charless-1";

    /**
     * 签发 Token
     *
     * @param payload 负载 Map
     * @return Token (字符串)
     */
    public static String issueToken(Map<String, Object> payload) {
        return issueToken(payload, JwtUtil.signKey, JwtUtil.expirationSeconds);
    }

    /**
     * 签发 Token
     *
     * @param payload           负载 Map
     * @param expirationSeconds 有效期 (秒)
     * @return Token (字符串)
     */
    public static String issueToken(Map<String, Object> payload, long expirationSeconds) {
        return issueToken(payload, JwtUtil.signKey, expirationSeconds);
    }

    /**
     * 签发 Token
     *
     * @param payload 负载 Map
     * @param signKey 签名密钥 (字符串 长度必须为 32)
     * @return Token (字符串)
     */
    public static String issueToken(Map<String, Object> payload, String signKey) {
        return issueToken(payload, signKey, JwtUtil.expirationSeconds);
    }

    /**
     * 签发 Token
     *
     * @param payload           负载 Map
     * @param signKey           签名密钥 (字符串 长度必须为 32)
     * @param expirationSeconds 有效期 (秒)
     * @return Token (字符串)
     */
    public static String issueToken(Map<String, Object> payload, String signKey, long expirationSeconds) {
        return Jwts.builder()
                .subject(JwtUtil.subject)
                .expiration(new Date(System.currentTimeMillis() + expirationSeconds * 1000))
                .signWith(Keys.hmacShaKeyFor(signKey.getBytes(StandardCharsets.UTF_8)))
                .claims(payload)
                .compact();
    }

    /**
     * 解析 Token
     *
     * @param token 待解析 Token (字符串)
     * @return 解析成功 -> 负载 Map; 解析失败 -> null
     */
    public static Map<String, Object> parseToken(String token) {
        return parseToken(token, JwtUtil.signKey);
    }

    /**
     * 解析 Token
     *
     * @param token   待解析 Token (字符串)
     * @param signKey 签名密钥 (字符串 长度必须为 32)
     * @return 解析成功 -> 负载 Map; 解析失败 -> null
     */
    public static Map<String, Object> parseToken(String token, String signKey) {
        if (CharSeqHelper.isEmpty(token)) {
            return null;
        }
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(signKey.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            if (claims.getExpiration() == null || claims.getExpiration().before(new Date())) {
                throw new ExpiredJwtException(null, null, "Token expired");
            }
            Map<String, Object> payload = DsGenerator.generateHashMap();
            claims.keySet().forEach(key -> payload.put(key, claims.get(key)));
            return payload;
        } catch (Exception err) {
            logger.error(err.getMessage(), err);
            return null;
        }
    }
}
