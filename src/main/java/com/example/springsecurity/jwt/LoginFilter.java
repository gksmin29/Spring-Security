package com.example.springsecurity.jwt;

import com.example.springsecurity.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
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

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        // username 추출
        String username = customUserDetails.getUsername();

        // role 추출
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // 토큰 생성
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // response에 담아 응답
        // Bearer 뒤에 띄어쓰기를 해야함에 유의
        response.addHeader("Authorization", "Bearer " + token);
    }

    // 인증이 실패했을 경우 동작
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException failed) {

        // 로그인 실패 시 401 응답 코드 전송
        response.setStatus(401);

    }
}
