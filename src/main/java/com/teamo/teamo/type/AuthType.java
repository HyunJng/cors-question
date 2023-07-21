package com.teamo.teamo.type;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AuthType {
    ROLE_USER("USER"),
    ROLE_ADMIN("ADMIN");

    private final String key;
}
