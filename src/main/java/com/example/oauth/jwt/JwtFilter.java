package com.example.oauth.jwt;

import com.example.oauth.jwt.domain.JwtConstants;
import com.example.oauth.jwt.domain.RefreshToken;
import com.example.oauth.jwt.repository.RefreshTokenRepository;
import com.example.oauth.jwt.service.JwtService;
import com.example.oauth.user.domain.User;
import com.example.oauth.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Principal;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    /*
     * 1. refreshToken x, accessToken valid     -> authentication success
     * 2. resfreshToken x, accessToken invalid  -> authentication fail
     * 3. refreshToken o                        -> reissue accessToken, refreshToken
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String refreshToken = jwtService.extractRefreshToken(request).orElse(null);

        if(refreshToken != null){
            refreshTokenRepository.findByRefreshToken(refreshToken)
                    .ifPresent(token -> { //리팩토링 필요
                                userRepository.findByEmail(token.getEmail()).ifPresent( user ->{
                                    String reissueRefreshToken = reIssueRefreshToken(token);
                                    String reissueAccessToken = jwtService.generateAccessToken(user);
                                    jwtService.setRefreshAccessTokenToHeader(response,reissueRefreshToken,reissueAccessToken);
                                });
                            });
            return;
        }

        String accessToken = jwtService.extractAccessToken(request).orElse(null);
        if(accessToken == null || !jwtService.isTokenValid(accessToken)){
            return;
        }

        String userEmail = jwtService.getUserEmail(accessToken);
        userRepository.findByEmail(userEmail)
                .ifPresent(user ->
                        saveAuthentication(user, accessToken));

        filterChain.doFilter(request, response);
    }

    private String reIssueRefreshToken(RefreshToken refreshToken) {
        String reIssuedRefreshToken = jwtService.generateRefreshToken();

        refreshToken.updateRefreshToken(reIssuedRefreshToken);
        refreshTokenRepository.saveAndFlush(refreshToken);

        return reIssuedRefreshToken;
    }

    private void saveAuthentication(User user, String accessToken){
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
}
