package cn.piao888.user.security;

import cn.piao888.user.domain.User;
import cn.piao888.user.mapper.UserMapper;
//import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


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
        List<String> roles = Arrays.asList("admin", "normal");
        List<GrantedAuthority> authorities = new ArrayList<>(roles.size());
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        userDetails.setUsername(userDO.getUsername());
        userDetails.setNickName(userDO.getNickname());
        userDetails.setId(userDO.getId());
        userDetails.setPassword(userDO.getPassword());
        userDetails.setAuthorities(authorities);
//        UserDetails userDetails = org.springframework.security.core.userdetails.User.withUsername(userDO.getUsername())
//                .password(userDO.getPassword())
//                .roles("admin", "normal")
//                .authorities("app", "web", "message.write")
//                .build();
        return userDetails;
    }
}