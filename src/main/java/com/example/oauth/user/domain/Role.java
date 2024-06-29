package com.example.oauth.user.domain;


import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER("ROLE_USER","일반회원"),
    GUEST("ROLE_GEUST", "회원가입 필요한 회원");

    private final String key;
    private final String title;
}
