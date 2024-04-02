package cn.piao888.user.security.config.oauth2;

import cn.piao888.user.security.UserInfo;
import cn.piao888.user.security.config.device.DeviceClientAuthenticationConverter;
import cn.piao888.user.security.config.device.DeviceClientAuthenticationProvider;
import cn.piao888.user.security.config.utils.SecurityUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 认证配置
 * {@link EnableMethodSecurity} 开启全局方法认证，启用JSR250注解支持，启用注解 {@link Secured} 支持，
 * 在Spring Security 6.0版本中将@Configuration注解从@EnableWebSecurity, @EnableMethodSecurity, @EnableGlobalMethodSecurity
 * 和 @EnableGlobalAuthentication 中移除，使用这些注解需手动添加 @Configuration 注解
 * {@link EnableWebSecurity} 注解有两个作用:
 * 1. 加载了WebSecurityConfiguration配置类, 配置安全认证策略。
 * 2. 加载了AuthenticationConfiguration, 配置了认证信息。
 *
 * @author vains
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class AuthorizationConfig {

    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";
    // 新建设备码converter和provider


    /**
     * 配置端点的过滤器链
     *
     * @param http spring security核心配置类
     * @return 过滤器链
     * @throws Exception 抛出
     */
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, RegisteredClientRepository registeredClientRepository, AuthorizationServerSettings authorizationServerSettings) throws Exception {
        //提供 登陆认证功能 、授权功能
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // 新建设备码converter和provider
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter = new DeviceClientAuthenticationConverter(authorizationServerSettings.getDeviceAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider = new DeviceClientAuthenticationProvider(registeredClientRepository);
        // 配置默认的设置，忽略认证端点的csrf校验

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // 开启OpenID Connect 1.0协议相关端点  提供开放接口文档 获取功能、退出接口功能、查询用户资料接口功能
                .oidc(Customizer.withDefaults())
                // 设置自定义用户确认授权页
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
                .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint -> deviceAuthorizationEndpoint.verificationUri("/activate"))
                .deviceVerificationEndpoint(deviceVerificationEndpoint -> deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
                .clientAuthentication(clientAuthentication ->
//                         客户端认证添加设备码的converter和provider
                        clientAuthentication.authenticationConverter(deviceClientAuthenticationConverter).authenticationProvider(deviceClientAuthenticationProvider));
        resourcesServerSecurityFilterChain(http);
        return http.build();
    }

    public void resourcesServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 当未登录时访问认证端点时重定向至login页面
                .exceptionHandling((exceptions) ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login")
                                , new MediaTypeRequestMatcher(MediaType.ALL)))
                // 处理使用access token访问用户信息端点和客户端注册端点
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .accessDeniedHandler(SecurityUtils::exceptionHandler)
                        .authenticationEntryPoint(SecurityUtils::exceptionHandler)
                );

    }

    /**
     * 配置认证相关的过滤器链
     *
     * @param http spring security核心配置类
     * @return 过滤器链
     * @throws Exception 抛出
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                        // 放行静态资源
                        .requestMatchers("/assets/**", "/webjars/**", "/login", "/no-authorization").permitAll()
                        .requestMatchers("/has-write").hasAuthority("message.write")
                        .requestMatchers("/has-normal-role").hasRole("normal")
                        .anyRequest().authenticated())
                // 指定登录页面
                .formLogin(formLogin -> formLogin.loginPage("/login"));
        // 添加BearerTokenAuthenticationFilanonymouster，将认证服务当做一个资源服务，解析请求头中的token
        http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    /**
     * 配置密码解析器，使用BCrypt的方式对密码进行加密和验证
     *
     * @return BCryptPasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * 配置客户端Repository
     *
     * @param jdbcTemplate    db 数据源信息
     * @param passwordEncoder 密码解析器
     * @return 基于数据库的repository
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // 客户端id
                .clientId("messaging-client")
                // 客户端秘钥，使用密码解析器加密
                .clientSecret(passwordEncoder.encode("123456"))
                // 客户端认证方式，基于请求头的认证
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 配置资源服务器使用该客户端获取授权时支持的方式
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // 授权码模式回调地址，oauth2.1已改为精准匹配，不能只设置域名，并且屏蔽了localhost，本机使用127.0.0.1访问
                .redirectUri("http://127.0.0.1:8882/login/oauth2/code/messaging-client-oidc").redirectUri("https://www.baidu.com")
                // 该客户端的授权范围，OPENID与PROFILE是IdToken的scope，获取授权时请求OPENID的scope时认证服务会返回IdToken
                .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
                // 自定scope
                .scope("message.read").scope("message.write")
                // 客户端设置，设置用户需要确认授权
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();

        // 基于db存储客户端，还有一个基于内存的实现 InMemoryRegisteredClientRepository
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // 初始化客户端
        RegisteredClient repositoryByClientId = registeredClientRepository.findByClientId(registeredClient.getClientId());
        if (repositoryByClientId == null) {
            registeredClientRepository.save(registeredClient);
        }
        // 设备码授权客户端
        RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("device-message-client")
                // 公共客户端
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                // 设备码授权
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 自定scope
                .scope("message.read").scope("message.write").build();
        RegisteredClient byClientId = registeredClientRepository.findByClientId(deviceClient.getClientId());
        if (byClientId == null) {
            registeredClientRepository.save(deviceClient);
        }
        return registeredClientRepository;
    }

    /**
     * 配置基于db的oauth2的授权管理服务
     *
     * @param jdbcTemplate               db数据源信息
     * @param registeredClientRepository 上边注入的客户端repository
     * @return JdbcOAuth2AuthorizationService
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        // 基于db的oauth2认证服务，还有一个基于内存的服务实现InMemoryOAuth2AuthorizationService
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 自定义jwt，将权限信息放至jwt中
     *
     * @return OAuth2TokenCustomizer的实例
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            // 检查登录用户信息是不是UserDetails，排除掉没有用户参与的流程
            if (context.getPrincipal().getPrincipal() instanceof UserInfo user) {
                // 获取申请的scopes
                Set<String> scopes = context.getAuthorizedScopes();
                // 获取用户的权限
                Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
                // 提取权限并转为字符串
                Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptyList()).stream()
                        // 获取权限字符串
                        .map(GrantedAuthority::getAuthority)
                        // 去JwtGrantedAuthoritiesConverter重
                        .collect(Collectors.toSet());

                // 合并scope与用户信息
                authoritySet.addAll(scopes);
                JwtClaimsSet.Builder claims = context.getClaims();
                // 将权限信息放入jwt的claims中（也可以生成一个以指定字符分割的字符串放入）
                claims.claim("authorities", authoritySet);
                claims.subject(String.valueOf(user.getId()));
                claims.claim("username", user.getUsername());
                claims.claim("nickname", user.getNickName());
                // 放入其它自定内容
                // 角色、头像...
            }
        };
    }

    /**
     * 自定义jwt解析器，设置解析出来的权限信息的前缀与在jwt中的key
     *
     * @return jwt解析器 JwtAuthenticationConverter
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // 设置解析权限信息的前缀，设置为空是去掉前缀
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        // 设置权限信息在jwt claims中的key
        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }


    /**
     * 配置基于db的授权确认管理服务
     *
     * @param jdbcTemplate               db数据源信息
     * @param registeredClientRepository 客户端repository
     * @return JdbcOAuth2AuthorizationConsentService
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        // 基于db的授权确认管理服务，还有一个基于内存的服务实现InMemoryOAuth2AuthorizationConsentService
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 配置jwk源，使用非对称加密，公开用于检索匹配指定选择器的JWK的方法
     *
     * @return JWKSource
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKey = new X509EncodedKeySpec(Base64.getDecoder().decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzT+lMxzjhPcIzn+mz/kJ1wq9GPyF6WADU4prUKPj1HrqDOgYWAllkG1EKS14dpy8obRxA1k2Kv/mnefCGaLvSsqZAh/Mgv5AxC9CdUnblfifaWdiRSuOjfWuDPA17d21L3qwdk3Q1tErgsBkFiTeryUzN2e+AmrqOoJTLKQrQutWsDwTzD5NAz9wCP06NyKZ4xFGgyJwqXEJY3kNuC+3+aDjhqB2tN+QzBCi3ItZDjNS0mPAFjI9VqSjyJj4wAjEpculYx/voB06FQ0TQHWQdOMedoPl6J9FPQcHEMQtletYfGjmIbK5B9lricTeQAFerODev3Sz65E2a5ayF4BgWQIDAQAB"));
        PKCS8EncodedKeySpec privateKey = new PKCS8EncodedKeySpec(Base64.getDecoder().decode("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNP6UzHOOE9wjOf6bP+QnXCr0Y/IXpYANTimtQo+PUeuoM6BhYCWWQbUQpLXh2nLyhtHEDWTYq/+ad58IZou9KypkCH8yC/kDEL0J1SduV+J9pZ2JFK46N9a4M8DXt3bUverB2TdDW0SuCwGQWJN6vJTM3Z74Cauo6glMspCtC61awPBPMPk0DP3AI/To3IpnjEUaDInCpcQljeQ24L7f5oOOGoHa035DMEKLci1kOM1LSY8AWMj1WpKPImPjACMSly6VjH++gHToVDRNAdZB04x52g+Xon0U9BwcQxC2V61h8aOYhsrkH2WuJxN5AAV6s4N6/dLPrkTZrlrIXgGBZAgMBAAECggEAF+7l+pHRzf1oX3vvHa0ygorUBgfcLZxuht1LKjoSJQK4LA0cWZeu6ipzmkGdHGemb0y1KOjMMjNo1tzhe0/Oi3AYa3D9zgCL2NSR8U9Nda1qGUZe5SXxF4igZQ3VnAkQSZsK3KCyS3pUkoiQoyxlcxLpZ/qG441IBs6PmFMEYGcPJI8NqXxCYPtoPZerToQ+Kd2ks9+jsJmLvtVKQzjCYBpfEI6A7hI8pYbC5735Q31+G+C6vKsb//B0XIFya1h0LdzWAPIqd0f2OzG9oe9EeYJGsrl5xPHRsO82UemDv8S5kKghm+5RWErZubChvjV7dQB0qiGj71Ri9DTrplLHSQKBgQD7E6h3iXCM/Wj8UGDANxC/YT5e8b4YSN0WiCMF0PFx32qtdTZSuuQFGptx3lMlZvW7lyVOKzWm4PH8R3FX8AsC1CcO7P95XGjlUWpoB6eDYvcUZRFYcKUS0MuKO02CGMuvYuPwhl90cjos85ik+2dhP82N/mvchqVa1R5/vSTn3wKBgQDRRfD/medqOTuC5W+f6j5RSo6MIbHPSn5/Z/9dk6mNKJdi7Pto5fph9hVvwOMDbrxdXbhLR7efzetTHySVD61gDthhvb3+jqk5ys4feX62Jbp0KOQZFCnyAyYj471dQkiNP8kWbwq7r8/RS2QNWyOMYkqqx6g6UWoBfSX+p9wexwKBgHHMTyce3CyLDvKNW8zDKIwVfzd5Sjenjs2PlpAkS8rZAHjuD1kf7AmELcBGjFj/eZE0yGvNmduxSPyXRQAehF8b2TgiowhWohSN+jR8g6hBSsuro1j6dVc524cjqdW1d1xe7gEuZkVZIJUPM7hTWl/xkzEwh6LERF4PCmvLRtbxAoGAQTl1VZTYRYk0/SUZV1QgvCFqsE5IJv1m07rMIpRFQhOmq1SFPzp+gU27fKs3lfhLiSYOrJfbqVj6wVtxgWvzc37s/fmvX8mDANouyCyLy6WSqWWdQhvAvwcwOftfJ9Pi3PNGb1GInNq9ANRoiKkhOT3hW70Ct7psOa6Ryv7yYj0CgYEA0mFvfZwQxa+kiiZFQidY9Dt9ozwf1FboKyvGhErR2LwTjl8M2MJWkGDpPaG7NaZyNirI2enLbChpwEuEU9a5uzvmTBWqOO82e3cjH843XRdZ0MqrSpmXNqVxxvTXuHVLKJXdQjPs4Mte8FUgbwhkn8GoRna+vRHdFWrnvfupkcY="));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyFactory.generatePublic(publicKey))
                .privateKey((RSAPrivateKey) keyFactory.generatePrivate(privateKey))
                .keyID("1").build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    public static void main(String[] args) {
        //生成密码
        System.out.println(new BCryptPasswordEncoder().encode("rr998xhz1997"));
        //生成jwt 密钥对
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println();
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
    }

    /**
     * 生成rsa密钥对，提供给jwk
     *
     * @return 密钥对
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 添加认证服务器配置，设置jwt签发者、默认端点请求地址OAuth2TokenGenerator等
     *
     * @return AuthorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}