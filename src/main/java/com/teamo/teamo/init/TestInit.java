package com.teamo.teamo.init;

import com.teamo.teamo.model.domain.Member;
import com.teamo.teamo.repository.MemberRepository;
import com.teamo.teamo.type.AuthType;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TestInit {

    private final MemberRepository memberRepository;

    @PostConstruct
    private void adminMemberSave() {
        Member member = Member.builder()
                .email("admin@gmail.com")
                .role(AuthType.ROLE_ADMIN)
                .build();

        memberRepository.save(member);
    }

}
