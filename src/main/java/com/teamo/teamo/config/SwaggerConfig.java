package com.teamo.teamo.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition(
        info = @Info(title = "Teamo App",
                description = "Teamo App API 명세",
                version = "v1"
        ))
@Configuration
public class SwaggerConfig {

}
