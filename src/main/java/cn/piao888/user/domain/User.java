package cn.piao888.user.domain;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

import java.time.LocalDate;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/7/31 15:18
 * @Version 1.0
 */
@Data
public class User {
    @TableId
    private Long id;
    private String nickName;
    private String username;
    private String password;
    private String secret;
    private LocalDate expirationTime;
    private Long limitCount;
    /**
     * 手机号
     */
    @TableField("mobile")
    private String mobile;
}
