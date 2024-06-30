package com.example.oauth.user.domain;


import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum LoginType {

    GOOGLE("google");

    private final String registrationId;
}
