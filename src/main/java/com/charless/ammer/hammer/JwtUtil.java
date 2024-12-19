package com.charless.ammer.hammer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 签发与解析 Java Web Token
 * { jjwt-api jjwt-impl jjwt-jackson slf4j logback }
 *
 * @author charix
 * @version 1.0
 */
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    /**
     * 签发 Token
     *
     * @param subject           标识主体
     * @param expirationSeconds 有效期 (秒)
     * @param signKey           签名密钥 (长度必须为 32 的字符串)
     * @param payload           负载 (Map)
     * @return 签发成功 -> Token; 签发失败 -> null
     */
    public static String issueToken(String subject, long expirationSeconds, String signKey, Map<String, Object> payload) {
        if (expirationSeconds <= 0 || signKey.length() != 32) {
            return null;
        }
        return Jwts.builder()
                .subject(subject)
                .expiration(new Date(System.currentTimeMillis() + expirationSeconds * 1000))
                .signWith(Keys.hmacShaKeyFor(signKey.getBytes(StandardCharsets.UTF_8)))
                .claims(payload)
                .compact();
    }

    /**
     * 签发 Token
     *
     * @param expirationSeconds 有效期 (秒)
     * @param signKey           签名密钥 (长度必须为 32 的字符串)
     * @param payload           负载 (Map)
     * @return 签发成功 -> Token; 签发失败 -> null
     */
    public static String issueToken(long expirationSeconds, String signKey, Map<String, Object> payload) {
        if (expirationSeconds <= 0 || signKey.length() != 32) {
            return null;
        }
        return Jwts.builder()
                .expiration(new Date(System.currentTimeMillis() + expirationSeconds * 1000))
                .signWith(Keys.hmacShaKeyFor(signKey.getBytes(StandardCharsets.UTF_8)))
                .claims(payload)
                .compact();
    }

    /**
     * 解析 Token
     *
     * @param token   待解析 Token (字符串)
     * @param signKey 签名密钥 (长度必须为 32 的字符串)
     * @return 解析成功 -> 负载 (Map); 解析失败 -> null
     */
    public static Map<String, Object> parseToken(String token, String signKey) {
        if (token.isEmpty() || signKey.length() != 32) {
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
            Map<String, Object> payload = new HashMap<>();
            claims.keySet().forEach(key -> payload.put(key, claims.get(key)));
            return payload;
        } catch (Exception err) {
            logger.error(err.getMessage(), err);
            return null;
        }
    }

}
