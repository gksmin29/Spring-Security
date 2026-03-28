package com.example.springsecurity.jwt;

import com.example.springsecurity.dto.CustomUserDetails;
import com.example.springsecurity.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 요청에 대해서 한 번만 동작하는 필터를 상속
public class JWTFilter extends OncePerRequestFilter {

    private JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // request에서 authorization 헤더 찾기
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 검증
        if ((authorization == null) || !authorization.startsWith("Bearer")) {
            System.out.println("token null");
            filterChain.doFilter(request, response);

            // 조건이 해당되면 메서드 종료 (필수)
            return;
        }

        System.out.println("authorization now");
        // Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        // 토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            // request, response를 다음 필터로 넘긴다.
            filterChain.doFilter(request, response);

            // 조건이 해당되면 메서드 종료 (필수)
            return;
        }

        // 토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temp");  // context holder에 임시로 비밀번호 값을 넣어준다.
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails,
                null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
