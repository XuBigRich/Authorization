package cn.piao888.user.security;

import cn.piao888.user.constants.Constants;
import cn.piao888.user.utils.StringUtils;
import cn.piao888.user.vo.response.CurrentUserVo;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;


/**
 * 安全服务工具类
 *
 * @author ruoyi
 */
public class SecurityUtils {
    /**
     * 获取用户账户
     **/
    public static String getUsername() throws Exception {
        try {
            return getLoginUser().getUserName();
        } catch (Exception e) {
            throw new Exception("获取用户账户异常");
        }
    }
    // 令牌自定义标识
//    @Value("${token.header}")
    private static String header="Bearer ";
    public static String getToken(HttpServletRequest request) {
        String token = request.getHeader(header);
        if (StringUtils.isNotEmpty(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
            token = token.replace(Constants.TOKEN_PREFIX, "");
        }
        return token;
    }
    /**
     * 获取用户
     **/
    public static CurrentUserVo getLoginUser() throws Exception {
        try {
            CurrentUserVo result = (CurrentUserVo) getAuthentication().getPrincipal();
            StackTraceElement stackTraceElement[] = new Throwable().getStackTrace();
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("获取用户信息异常");
        }
    }


    /**
     * 获取Authentication
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 生成BCryptPasswordEncoder密码
     *
     * @param password 密码
     * @return 加密字符串
     */
    public static String encryptPassword(String password) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(password);
    }

    /**
     * 判断密码是否相同
     *
     * @param rawPassword     真实密码
     * @param encodedPassword 加密后字符
     * @return 结果
     */
    public static boolean matchesPassword(String rawPassword, String encodedPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    /**
     * 是否为管理员
     *
     * @param userId 用户ID
     * @return 结果
     */
    public static boolean isAdmin(Long userId) {
        return userId != null && 1L == userId;
    }

    /**
     * 获取当前登陆用户的角色
     **/

}

