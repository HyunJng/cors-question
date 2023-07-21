package com.teamo.teamo.service;

import com.teamo.teamo.model.domain.Member;
import com.teamo.teamo.model.request.ReissueRequest;
import com.teamo.teamo.repository.MemberRepository;
import com.teamo.teamo.security.token.JwtDto;
import com.teamo.teamo.type.AuthType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class MemberService {

    private final MemberRepository memberRepository;
    private final JwtService jwtService;

    @Transactional
    public JwtDto login(OAuth2User oAuth2User) {
        // 1. 회원 아니라면 회원가입
        if (!memberRepository.existsByEmail(oAuth2User.getAttribute("email"))) {
            memberRepository.save(Member.builder()
                    .email(oAuth2User.getAttribute("email"))
                    .role(AuthType.ROLE_USER)
                    .build());
        }
        // 2. 회원은 token을 생성
        return jwtService.generateJwtDto(oAuth2User.getAttribute("email"));
    }

    @Transactional(readOnly = true)
    public JwtDto reissue(ReissueRequest request) {
        jwtService.validateRefreshToken(request.getRefreshToken());
        Authentication authentication = jwtService.findAuthentication(request.getRefreshToken());

        return jwtService.generateJwtDto(authentication.getName());
    }

}
