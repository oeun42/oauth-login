package com.example.oauth.auth.handler;

import com.example.oauth.auth.domain.CustomOAuth2User;
import com.example.oauth.user.domain.Role;
import com.example.oauth.user.domain.User;
import com.example.oauth.user.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User user = ((CustomOAuth2User) authentication.getPrincipal()).getUser();
        //jwt 생성 로직

        if(user.getRole() == Role.GUEST){ //회원가입
            userRepository.save(user);
        }
    }
}
