package com.teamo.teamo.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "demo", description = "demo api")
@RestController
@RequestMapping("/test")
public interface DemoApi {

    @Operation(summary = "테스트", description = "테스트 메서드입니다")
    @GetMapping
    String test();
}
