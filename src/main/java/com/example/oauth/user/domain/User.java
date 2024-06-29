package com.example.oauth.user.domain;



import jakarta.persistence.*;
import lombok.*;

@Getter
@Entity
@Table(name = "TB_USER")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id @GeneratedValue
    private Long userId;

    private String name;

    private String email;

    private String password;

    private String picture;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private LoginType loginType;

    @Builder
    public User(String name, String email, String picture, Role role){
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.role = role;
    }

    public void updateUserRole(Role newRole){
        this.role = newRole;
    }
}
