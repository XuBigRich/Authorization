package cn.piao888.user.vo.response;

import lombok.Data;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/3/20 2:31 下午
 * @Version 1.0
 */
@Data
public class CurrentUserVo {
    private Long id;
    private String nickName;
    private String userName;
    private String requestDate;
    private String token;
    private Long expireTime;
    private Long loginTime;

}
