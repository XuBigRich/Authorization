package cn.piao888.user.security.config.filter;

import java.io.IOException;

import cn.piao888.user.security.SecurityUtils;
import cn.piao888.user.security.UserInfo;
import cn.piao888.user.security.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * token过滤器 验证token有效性
 *
 * @author ruoyi
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private TokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final Authentication authentication = SecurityUtils.getAuthentication();
        if (authentication== null && tokenService.getToken(request) != null) {
            BearerTokenAuthenticationToken authenticationToken = new BearerTokenAuthenticationToken(tokenService.getToken(request));
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            //如果不设置Security默认当前用户没有通过认证，那么 后续请求将会被拒绝
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }
        chain.doFilter(request, response);
    }
}
