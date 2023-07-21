package com.teamo.teamo.model.domain;

import com.teamo.teamo.type.AuthType;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "MEMBER_TABLE")
@NoArgsConstructor
@Entity
public class Member {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "MEMBER_ID")
    private Long id;

    private String email;

    @Enumerated(EnumType.STRING)
    private AuthType role;

    @Builder
    public Member(String email, AuthType role) {
        this.email = email;
        this.role = role;
    }
}
