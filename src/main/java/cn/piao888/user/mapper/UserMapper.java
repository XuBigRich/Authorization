package cn.piao888.user.mapper;

import cn.piao888.user.domain.User;
import cn.piao888.user.security.UserInfo;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/3/20 3:54 下午
 * @Version 1.0
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {
    UserInfo getUserByUsername(@Param("username") String username);
}
