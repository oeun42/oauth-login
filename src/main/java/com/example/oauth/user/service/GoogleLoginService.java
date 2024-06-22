package com.example.oauth.user.service;

import com.example.oauth.user.dto.Request.GoogleAccessTokenRequest;
import com.example.oauth.user.dto.Response.AuthResponse;
import com.example.oauth.user.dto.Response.UserInfoResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class GoogleLoginService {

    @Value("${oauth2.google.login-uri}")
    private String googleLoginUri;

    @Value("${oauth2.google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${oauth2.google.resource-uri}")
    private String googleResourceUri;

    @Value("${oauth2.google.token-uri}")
    private String googleTokenUri;

    @Value("${oauth2.google.client-id}")
    private String googleClientId;

    @Value("${oauth2.google.client-secret}")
    private String googleClientSecret;

    @Value("${oauth2.google.grant-type}")
    private String googleGrantType;

    @Autowired
    private WebClient webClient;


    public String getGoogleLoginUri(){
        String uri = googleLoginUri + "?client_id=" + googleClientId + "&redirect_uri=" +googleRedirectUri +
                "&response_type=code&scope=https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";

        return uri;
    }

    public UserInfoResponse socialLogin(String code) {
        AuthResponse authResponse = getAccessToken(code);
        UserInfoResponse userInfo = getUserInfo(authResponse.getAccess_token());

        return userInfo;
    }
    private AuthResponse getAccessToken(String authorizationCode){
        GoogleAccessTokenRequest accessRequestToken = GoogleAccessTokenRequest.builder()
                .code(authorizationCode)
                .client_id(googleClientId)
                .client_secret(googleClientSecret)
                .redirect_uri(googleRedirectUri)
                .grant_type(googleGrantType)
                .build();

        return  webClient.post()
                .uri(googleTokenUri)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(accessRequestToken)
                .retrieve()
                .bodyToMono(AuthResponse.class)
                .block();
    }


    private UserInfoResponse getUserInfo(String accessToken){
        return webClient.get()
                .uri(googleResourceUri)
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(UserInfoResponse.class)
                .block();
    }
}
