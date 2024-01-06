package cn.piao888.user.vo.req;

import lombok.Data;

import javax.validation.constraints.NotNull;

/**
 * 用户登录对象
 *
 * @author ruoyi
 */
@Data
public class LoginBody {
    /**
     * 用户名
     */
    private String username;

    /**
     * 用户密码
     */
    private String password;

    private String clientId;

    /**
     * 验证码
     */
    private String verificationCode;

    /**
     * 唯一标识
     */
    private String uuid = "";

    /**
     * 登陆方式 0.验证码 1.账号密码
     */
    @NotNull(message = "登陆方式不能为空!")
    private Integer loginType;

}
