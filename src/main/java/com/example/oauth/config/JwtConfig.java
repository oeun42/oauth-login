package com.example.oauth.config;

import com.example.oauth.jwt.JwtFilter;
import com.example.oauth.jwt.handler.JwtAccessDeniedHandler;
import com.example.oauth.jwt.handler.JwtAuthenticationEntryPoint;
import com.example.oauth.jwt.service.JwtService;
import com.example.oauth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final JwtService jwtService;
    private final UserService userService;
    private final JwtAuthenticationEntryPoint authenticationEntryPoint;
    private final JwtAccessDeniedHandler accessDeniedHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(new JwtFilter(jwtService, userService), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionConfig -> exceptionConfig
                            .authenticationEntryPoint(authenticationEntryPoint)
                            .accessDeniedHandler(accessDeniedHandler));
    }
}
