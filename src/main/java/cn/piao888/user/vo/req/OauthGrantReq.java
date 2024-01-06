package cn.piao888.user.vo.req;

import lombok.Data;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/10/26 10:04
 * @Version 1.0
 */
@Data
public class OauthGrantReq {
    private String client_id;
    private String redirect_uri;
    private String response_type;
}
