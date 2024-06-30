package com.example.oauth.auth.handler;

import com.example.oauth.auth.domain.CustomOAuth2User;
import com.example.oauth.jwt.domain.RefreshToken;
import com.example.oauth.jwt.repository.RefreshTokenRepository;
import com.example.oauth.jwt.service.JwtService;
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
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${uri.login-success}")
    private String loginSuccessUri;

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User user = ((CustomOAuth2User) authentication.getPrincipal()).getUser();

        if(user.getRole() == Role.GUEST){
            this.signup(user);
        }

        createAccessRefreshToken(user, response);

        String redirectURL = UriComponentsBuilder
                .fromUriString(loginSuccessUri)
                .toUriString();

        getRedirectStrategy().sendRedirect(request, response, redirectURL);
    }

    public void signup(User user){
        user.updateUserRole(Role.USER);
        userRepository.save(user);
    }

    public void createAccessRefreshToken(User user, HttpServletResponse response){
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken();

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .email(user.getEmail())
                .refreshToken(refreshToken)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);
        jwtService.setRefreshAccessTokenToHeader(response, refreshToken, accessToken);
    }
}
