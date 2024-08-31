package cn.piao888.user.service.impl;

import cn.piao888.user.domain.User;
import cn.piao888.user.dubbo.UserDubboService;
import cn.piao888.user.mapper.UserMapper;
import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/3/20 3:44 下午
 * @Version 1.0
 */
@DubboService
public class UserServiceImpl implements UserDubboService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public User getUserByUsername(String username) {
        return userMapper.getUserByUsername(username);
    }
}
