package com.teamo.teamo.service;

import com.teamo.teamo.model.domain.Member;
import com.teamo.teamo.repository.MemberRepository;
import com.teamo.teamo.security.AuthConst;
import com.teamo.teamo.security.CustomUserDetailsService;
import com.teamo.teamo.security.dto.MemberLoginDto;
import com.teamo.teamo.security.token.JwtDto;
import com.teamo.teamo.type.AuthType;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class JwtService {

    private final String AUTHORITIES_KEY = "auth";
    private final Integer ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;
    private final Integer REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;

    @Value("ZVc3Z0g4bm5TVzRQUDJxUXBIOGRBUGtjRVg2WDl0dzVYVkMyWW")
    private String secretKey;
    private Key key;

    private final MemberRepository memberRepository;
    private final CustomUserDetailsService customUserDetailsService;

    @PostConstruct
    private void initialize() {
        // key 인코딩
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        key = Keys.hmacShaKeyFor(encodedKey.getBytes());
    }

    @Transactional(readOnly = true)
    public JwtDto generateJwtDto(String email) {
        Date now = new Date();
        Date accessTokenExpiresIn = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);
        Date refreshTokenExpiresIn = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_TIME);
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("해당 email의 유저가 존재하지 않습니다"));

        String accessToken = generateAccessToken(member.getEmail(), member.getRole(), accessTokenExpiresIn);
        String refreshToken = generateRefreshToken(member.getEmail(), member.getRole(), refreshTokenExpiresIn);

        return JwtDto.builder()
                .grantType(AuthConst.BEARER)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .build();
    }

    public String generateAccessToken(String email, AuthType role, Date accessExpireDate) {

        return Jwts.builder()
                .setSubject(email)
                .claim(AUTHORITIES_KEY, role)
                .setExpiration(accessExpireDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(String email, AuthType role, Date refreshExpireDate) {
        return Jwts.builder()
                .setSubject(email)
                .claim(AUTHORITIES_KEY, role)
                .setExpiration(refreshExpireDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AuthConst.AUTHORIZATION);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(AuthConst.BEARER)) {
            return bearerToken.substring(7);
        } else if (StringUtils.hasText(bearerToken) && bearerToken.equals(AuthConst.DEBUG_MODE)) {
            return AuthConst.DEBUG_MODE;
        }
        return "";
    }

    public Boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException e) {
            log.error("올바르지 못한 토큰입니다");
        } catch (MalformedJwtException e) {
            log.error("올바르지 못한 토큰입니다");
        } catch (ExpiredJwtException e) {
            log.error("만료된 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("잘못된 토큰입니다.");
        }

        return false;
    }

    public Authentication findAuthentication(String token) {
        Claims claims = parseClaims(token);

        MemberLoginDto memberLoginDto = customUserDetailsService.loadUserByUsername(claims.getSubject());
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority((String)claims.get(AUTHORITIES_KEY)));
        return new UsernamePasswordAuthenticationToken(memberLoginDto, "", authorities);
    }

    private Claims parseClaims(String accessToken) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
    }

    public void validateRefreshToken(String refreshToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(refreshToken);
        } catch (SecurityException e) {
            log.error("올바르지 못한 토큰입니다");
        } catch (MalformedJwtException e) {
            log.error("올바르지 못한 토큰입니다");
        } catch (ExpiredJwtException e) {
            log.error("만료된 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("잘못된 토큰입니다.");
        }
    }
}
