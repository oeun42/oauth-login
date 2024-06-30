package com.example.oauth.auth.domain;

import com.example.oauth.user.domain.User;
import lombok.Data;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;


@Getter
public class CustomOAuth2User extends DefaultOAuth2User {

    private User user;

    public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities
            , Map<String, Object> attributes, String nameAttributeKey, User user) {
        super(authorities, attributes, nameAttributeKey);
        this.user = user;
    }
}
