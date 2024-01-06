package cn.piao888.user.dubbo;


import cn.piao888.user.security.UserInfo;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/3/20 3:45 下午
 * @Version 1.0
 */
public interface UserDubboService {
    UserInfo getUserByUsername(String username);
}
