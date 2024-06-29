package com.example.oauth.jwt.domain;

import com.example.oauth.user.domain.User;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    @Id
    private String email;
    private String refreshToken;

    @OneToOne(mappedBy = "email")
    private User user;

    @Builder
    public RefreshToken(String email, String refreshToken){
        this.email = email;
        this.refreshToken = refreshToken;
    }

    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }
}
