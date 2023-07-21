package com.teamo.teamo.filter;

import com.teamo.teamo.model.domain.Member;
import com.teamo.teamo.security.AuthConst;
import com.teamo.teamo.security.dto.MemberLoginDto;
import com.teamo.teamo.service.JwtService;
import com.teamo.teamo.type.AuthType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@AllArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /* cors */
        response.setHeader("Access-Control-Allow-Origin", "*"); // 모든 Origin 허용, 필요에 따라 필요한 Origin을 설정할 수도 있습니다.
        response.setHeader("Access-Control-Allow-Credentials", "true"); // 자격 증명 허용 (즉, 인증된 요청 허용)
        response.setHeader("Access-Control-Allow-Methods", "HEAD, GET, POST, PUT, DELETE, PATCH, OPTIONS"); // 허용할 HTTP 메서드 목록
        response.setHeader("Access-Control-Max-Age", "3600"); // Preflight 요청에 대한 캐시 유지 시간
        response.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Key, Authorization"); // 허용할 헤더 목록

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            filterChain.doFilter(request, response);
        }

        String jwt = jwtService.resolveToken(request);

        // debug 모드
        if (StringUtils.hasText(jwt) && jwt.equals(AuthConst.DEBUG_MODE)) {
            log.info("debug mode");
            // todo: debug 모드일 때 Context에 저장된 User의 Id 정보 어떻게 처리할지 고민하기
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                    new MemberLoginDto(Member.builder()
                            .role(AuthType.ROLE_ADMIN)
                            .email("admin@gmail.com")
                            .build()),
                    "",
                    List.of(new SimpleGrantedAuthority(AuthType.ROLE_ADMIN.toString()))));
        }

        // access token 인가
        else if (StringUtils.hasText(jwt) && jwtService.validateAccessToken(jwt)) {
            Authentication authentication = jwtService.findAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
