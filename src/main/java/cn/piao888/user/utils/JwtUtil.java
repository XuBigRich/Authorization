package cn.piao888.user.utils;

import cn.piao888.user.security.LoginUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtUtil {

    //    private static final String SECRET_KEY = "TOk4d0RpBTuNjUgvskt4IxpJxSgMiU/7j8kIDKhfa6I="; // 用于签名的密钥
    private static final long EXPIRATION_TIME = 864_000_000; // Token 过期时间 (10 days)

    public static String generateToken(LoginUser loginUser, String secret) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + EXPIRATION_TIME);
        return Jwts.builder()
                .setSubject(String.valueOf(loginUser.getId()))
                .claim("user", loginUser)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS512)
                .compact();
    }


    public static String extractUserId(String token, String secret) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public static LoginUser extractLoginUser(String token, String secret) {
        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
        Jwt jwt = new Jwt(token, claims.getIssuedAt().toInstant(), claims.getExpiration().toInstant(), claims, claims);
        Map<String, Object> principalClaim = jwt.getClaim("user");
        ObjectMapper objectMapper = new ObjectMapper();
        // 将 Map 转换为 User 对象
        LoginUser user = objectMapper.convertValue(principalClaim, LoginUser.class);
        return user;
    }

    public static boolean isTokenExpired(String token, String secret) {
        Date expirationDate = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expirationDate.before(new Date());
    }
}
