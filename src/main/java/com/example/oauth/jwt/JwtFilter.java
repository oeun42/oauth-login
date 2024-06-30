package com.example.oauth.jwt;

import com.example.oauth.jwt.domain.RefreshToken;
import com.example.oauth.jwt.repository.RefreshTokenRepository;
import com.example.oauth.jwt.service.JwtService;
import com.example.oauth.user.domain.User;
import com.example.oauth.user.repository.UserRepository;
import com.example.oauth.user.service.UserService;
import io.netty.handler.codec.http.HttpResponseStatus;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserService userService;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    private static final List<String> excludeUrls = Arrays.asList("http://localhost:8080/login-success");

    /*
     * 1. refreshToken x, accessToken valid     -> authentication success
     * 2. resfreshToken x, accessToken invalid  -> authentication fail
     * 3. refreshToken o                        -> reissue accessToken, refreshToken
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //로그인 페이지면 토큰 검증 X
        if(excludeFilterUrls(request)){
            filterChain.doFilter(request, response);
            return;
        }

        String refreshToken = jwtService.extractRefreshToken(request).orElse(null);

        if(refreshToken != null){
            if(!checkAndRefreshToken(request, response, refreshToken)){
               return;
            }
        }
        else{
            String accessToken = jwtService.extractAccessToken(request).orElse(null);

            if(accessToken == null || !jwtService.isTokenValid(accessToken)){
                return;
            }

            String userEmail = jwtService.getUserEmailFromToken(accessToken);
            userService.findByEmail(userEmail)
                    .ifPresent(user ->
                    saveAuthentication(request, response, user));
        }

        filterChain.doFilter(request, response);
    }

    public boolean checkAndRefreshToken(HttpServletRequest request, HttpServletResponse response, String token){
        RefreshToken refreshToken = jwtService.getRefreshToken(token).orElse(null);
        boolean isValidToken = false;

        if(refreshToken != null){
            String reissueRefreshToken = reIssueRefreshToken(refreshToken);
            String reissueAccessToken = jwtService.generateAccessToken(refreshToken.getUser());
            jwtService.setRefreshAccessTokenToHeader(response,reissueRefreshToken,reissueAccessToken);
            saveAuthentication(request, response, refreshToken.getUser());
            isValidToken = true;
        }

        return isValidToken;
    }

    private String reIssueRefreshToken(RefreshToken refreshToken) {
        String reIssuedRefreshToken = jwtService.generateRefreshToken();

        refreshToken.updateRefreshToken(reIssuedRefreshToken);
        jwtService.saveResfreshToken(refreshToken);

        return reIssuedRefreshToken;
    }

    private void saveAuthentication(HttpServletRequest request, HttpServletResponse response, User user) {
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password("")
                .roles(user.getRole().getKey())
                .build();

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails,
                null,
                authoritiesMapper.mapAuthorities(userDetails.getAuthorities()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private boolean excludeFilterUrls(HttpServletRequest request){
       return excludeUrls
               .stream()
               .anyMatch(url -> url.equals(request.getRequestURL().toString()));
    }
}
