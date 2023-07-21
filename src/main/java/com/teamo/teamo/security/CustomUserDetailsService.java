package com.teamo.teamo.security;

import com.teamo.teamo.model.domain.Member;
import com.teamo.teamo.repository.MemberRepository;
import com.teamo.teamo.security.dto.MemberLoginDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public MemberLoginDto loadUserByUsername(String email) throws UsernameNotFoundException {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("해당 이메일 유저가 없음"));
        return new MemberLoginDto(member);
    }
}
