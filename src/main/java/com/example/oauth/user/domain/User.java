package com.example.oauth.user.domain;



import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
public class User {

    @Id @GeneratedValue
    private Long userId;

    private String name;

    private String email;

    private String password;

    private String picture;

    @Enumerated(EnumType.STRING)
    private Role role;
}
