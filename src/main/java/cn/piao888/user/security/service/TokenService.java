package cn.piao888.user.security.service;

import java.util.Date;

import cn.piao888.user.constants.Constants;
import cn.piao888.user.security.LoginUser;
import cn.piao888.user.utils.JwtUtil;
import cn.piao888.user.utils.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * token验证处理
 *
 * @author ruoyi
 */
@Component
public class TokenService {
    // 令牌自定义标识
    @Value("${token.header}")
    private String header;

    // 令牌秘钥
    @Value("${token.secret}")
    private String secret;

    // 令牌有效期（默认30分钟）
    @Value("${token.expireTime}")
    private int expireTime;

    protected static final long MILLIS_SECOND = 1000;

    protected static final long MILLIS_MINUTE = 60 * MILLIS_SECOND;

    private static final Long MILLIS_MINUTE_TEN = 20 * 60 * 1000L;


    /**
     * 获取用户身份信息
     *
     * @return 用户信息
     */
    public LoginUser getLoginUser(HttpServletRequest request) {
        // 获取请求携带的令牌
        String token = getToken(request);
        if (StringUtils.isNotEmpty(token)) {
            //这个地方将token转换为Claims信息
            LoginUser user = JwtUtil.extractLoginUser(token, secret);
            return user;
        }
        return null;
    }



    /**
     * 创建令牌
     *
     * @param loginUser 用户信息
     * @return 令牌
     */
    public String createToken(LoginUser loginUser) {
        return Jwts.builder()
                .setSubject(loginUser.getName())
                .setIssuedAt(new Date())
                .claim("user", loginUser)
                .setExpiration(new Date((new Date()).getTime() + expireTime))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }


    /**
     * 刷新令牌有效期
     *
     * @param loginUser 登录信息
     */
    public String refreshToken(LoginUser loginUser) {
        final String token = JwtUtil.generateToken(loginUser, secret);
        return token;
    }


    /**
     * 从令牌中获取数据声明
     *
     * @param token 令牌
     * @return 数据声明
     */
    private Claims parseToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 获取请求token
     *
     * @param request
     * @return token
     */
    public String getToken(HttpServletRequest request) {
        String token = request.getHeader(header);
        if (StringUtils.isNotEmpty(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
            token = token.replace(Constants.TOKEN_PREFIX, "");
        }
        return token;
    }

}
