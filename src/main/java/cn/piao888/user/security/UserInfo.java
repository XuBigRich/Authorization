package cn.piao888.user.security;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @Author： hongzhi.xu
 * @Date: 2023/5/26 8:17 下午
 * @Version 1.0
 */
@Data
public class UserInfo implements UserDetails {
    private Long id;
    private String token;
    private String nickName;
    private String userName;
    private String password;
    private long loginTime;
    private long expireTime;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
