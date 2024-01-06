package cn.piao888.user.utils;

import cn.piao888.user.security.UserInfo;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;

import javax.json.Json;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtUtil {

//    private static final String SECRET_KEY = "TOk4d0RpBTuNjUgvskt4IxpJxSgMiU/7j8kIDKhfa6I="; // 用于签名的密钥
    private static final long EXPIRATION_TIME = 864_000_000; // Token 过期时间 (10 days)

    public static String generateToken(UserInfo userInfo,String secret) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + EXPIRATION_TIME);
        String jsonString = JSON.toJSONString(userInfo);
        JSONObject jsonObject = JSON.parseObject(jsonString);
        return Jwts.builder()
                .setSubject(String.valueOf(userInfo.getId()))
                .setClaims(jsonObject)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS256)
                .compact();
    }


    public static String extractUserId(String token,String secret) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public static UserInfo extractUserInfo(String token,String secret) {
        final Claims body = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
        UserInfo userInfo = JSON.parseObject(JSON.toJSONString(body), UserInfo.class);
        return userInfo;
    }

    public static boolean isTokenExpired(String token,String secret) {
        Date expirationDate = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expirationDate.before(new Date());
    }
}
