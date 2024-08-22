package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Data
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    // user가 가진 권한들을 `Collection` 형태로 반환 & spring security는 이 정보를 사용해 사용자가 특정 요청을 수행할 권한이 있는지를 확인
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // GrantedAuthority : Spring Security에서 사용자의 권한(사용자가 수행할 수 있는 작업이나 역할)을 나타내는 인터페이스
        //                      단순히 사용자가 어떤 권한을 가지고 있는지를 설명하는 역할
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // user의 roleList 메서드를 호출해 하나씩 권한들을 가져와 `authorities` 안에 추가하는 작업
        user.getRoleList().forEach(r->{
            authorities.add(()->r);
        });
        return authorities;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }
}
