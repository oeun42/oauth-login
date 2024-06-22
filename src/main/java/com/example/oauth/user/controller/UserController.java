package com.example.oauth.user.controller;

import com.example.oauth.user.dto.Response.UserInfoResponse;
import com.example.oauth.user.service.GoogleLoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @Autowired
    private GoogleLoginService googleLoginService;

    @GetMapping("/login/oauth2/google/uri")
    public ResponseEntity<String> getGoogleLoginUri(){
        return ResponseEntity.status(HttpStatus.OK).body(googleLoginService.getGoogleLoginUri());
    }

    @GetMapping(value ="/login/oauth2/code/google")
    public ResponseEntity<UserInfoResponse> googleLogin(@RequestParam String code){

        return ResponseEntity.status(HttpStatus.OK).body(googleLoginService.socialLogin(code));
    }
}
