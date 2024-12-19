package com.charless.ammer;

import com.charless.ammer.hammer.JwtUtil;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

public class JwtUtilTest {

    @Test
    public void testIssueAndParse() {
        String subject = "Authentication";
        long expiration = 60;
        String signKey = "a-custom-charless-amber-hammer-0";
        Map<String, Object> claims = new HashMap<>();
        claims.put("amber", "hammer");
        claims.put("author", "charix");
        claims.put("version", "1.0");

        String token = JwtUtil.issueToken(subject, expiration, signKey, claims);
        System.out.println("token = " + token);

        assert token != null;
        Map<String, Object> parsedPayload = JwtUtil.parseToken(token, signKey);
        assert parsedPayload != null;
        parsedPayload.keySet().forEach(key -> System.out.println(key + ": " + parsedPayload.get(key)));
    }

}
