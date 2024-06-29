package com.example.oauth.jwt.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.oauth.jwt.domain.JwtConstants;
import com.example.oauth.user.domain.User;
import com.example.oauth.utils.TimeUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;

import java.time.ZonedDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirePeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirePeriod;


    public String generateAccessToken(User user){
        ZonedDateTime zonedDateTime = TimeUtils.getCurrentTime();

        return JWT.create()
                .withSubject("AccessToken")
                .withClaim("email", user.getEmail())
                .withExpiresAt(Instant.from(zonedDateTime.plusSeconds(accessTokenExpirePeriod)))
                .sign(Algorithm.HMAC512(secretKey));
    }

    public String generateRefreshToken(){
        ZonedDateTime zonedDateTime = TimeUtils.getCurrentTime();

        return JWT.create()
                .withSubject("RefreshToken")
                .withExpiresAt(Instant.from(zonedDateTime.plusSeconds(refreshTokenExpirePeriod)))
                .sign(Algorithm.HMAC512(secretKey));
    }

    public String getUserEmail(String token){
        return JWT.require(Algorithm.HMAC512(secretKey)).build()
                .verify(token)
                .getClaim("email").toString();
    }

    public Optional<String> extractAccessToken(HttpServletRequest request){
        return Optional.ofNullable(request.getHeader(JwtConstants.ACCESS))
                .filter(accessToken -> accessToken.startsWith(JwtConstants.TOKEN_TYPE))
                .map(accessToken -> accessToken.replace(JwtConstants.TOKEN_TYPE, ""));

    }

    public Optional<String> extractRefreshToken(HttpServletRequest request){
        return Optional.ofNullable(request.getHeader(JwtConstants.REFRESH))
                .filter(accessToken -> accessToken.startsWith(JwtConstants.TOKEN_TYPE))
                .map(accessToken -> accessToken.replace(JwtConstants.TOKEN_TYPE, ""));
    }

    public boolean isTokenValid(String token){
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
            return true;
        }
        catch (Exception e){
            return false;
        }
    }

    public void setRefreshAccessTokenToHeader(HttpServletResponse response, String refreshToken, String accessToken){
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(JwtConstants.REFRESH, JwtConstants.TOKEN_TYPE + refreshToken);
        response.setHeader(JwtConstants.ACCESS, accessToken);
    }
}
