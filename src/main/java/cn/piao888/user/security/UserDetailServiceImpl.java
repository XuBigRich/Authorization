package cn.piao888.user.security;

import cn.piao888.user.domain.User;
import cn.piao888.user.mapper.UserMapper;
//import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;


/**
 * @author 许鸿志
 * @since 2022/5/13
 */
@Component
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    private UserMapper sysUserMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        QueryWrapper<User> userDOQueryWrapper = new QueryWrapper<>();
        //局端用户从本地查询
        User userDO = sysUserMapper.selectOne(userDOQueryWrapper.lambda().eq(User::getUsername, username));
        //学校端用户从用户中心查询
        //如果用户中心 和 局端数据库都没有信息 那么 抛出异常 账户不存在
        if (userDO == null) {
            return null;
        }
        UserInfo userDetails = new UserInfo();
        userDetails.setUserName(userDO.getUsername());
        userDetails.setNickName(userDO.getNickname());
        userDetails.setId(userDO.getId());
        userDetails.setPassword(userDO.getPassword());
        return userDetails;
    }
}