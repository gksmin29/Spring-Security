package com.example.springsecurity.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Optional;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // 내부에서는 로그인 진행을 위한 attempt 메서드를 override 해줘야 한다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        // username, password를 request에서 꺼내기
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println(username + password);

        // 추출한 정보를 AuthenticationManager에 전달하기 위해 DTO에 이 정보를 담을 것
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                username, password, null);

        // DTO를 AuthenticationManager에 전달
        return authenticationManager.authenticate(authToken);
    }

    // 인증이 성공했을 경우 동작
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                         FilterChain chain, Authentication authentication) {
    }

    // 인증이 실패했을 경우 동작
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException failed) {

    }
}
