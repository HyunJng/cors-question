package com.teamo.teamo.controller;

import com.teamo.teamo.api.DemoApi;
import com.teamo.teamo.security.dto.MemberLoginDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class TestController implements DemoApi {

    @Override
    public String test() {
        return "test 성공";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin 전용";
    }

    @GetMapping("/guest")
    public String guest(@AuthenticationPrincipal MemberLoginDto memberLoginDto) {
        log.info("Login member id = {}, email= {}", memberLoginDto.getMember().getId(), memberLoginDto.getMember().getEmail());
        return "guest 전용";
    }
}
