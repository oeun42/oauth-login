package com.example.oauth.config;

import com.example.oauth.auth.handler.CustomOAuth2SuccessHandler;
import com.example.oauth.auth.service.CustomOAuth2UserService;
import com.example.oauth.jwt.JwtFilter;
import com.example.oauth.jwt.service.JwtService;
import com.example.oauth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOAuth2SuccessHandler customOAuth2SuccessHandler;
    private final JwtService jwtService;
    private final UserService userService;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .headers((headerConfig) -> headerConfig
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .authorizeRequests((authorizeRequests) -> authorizeRequests
                                .requestMatchers("/","/oauth2/authorization/google").permitAll()
                                .anyRequest().authenticated())
                .logout((logoutConfig) ->
                        logoutConfig.logoutSuccessUrl("/"))
                .oauth2Login((oauth2) -> oauth2
                        .loginPage("/oauth2/authorization/google")
                        .successHandler(customOAuth2SuccessHandler)
                        .failureUrl("/failure")
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(customOAuth2UserService)));


        return http.build();
    }
}
