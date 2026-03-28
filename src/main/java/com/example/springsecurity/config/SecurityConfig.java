package com.example.springsecurity.config;

import com.example.springsecurity.jwt.JWTFilter;
import com.example.springsecurity.jwt.JWTUtil;
import com.example.springsecurity.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity  // 이 클래스는 security를 위한 config임을 명시
// 이 클래스 안의 메서드들을 bean으로 등록해둠으로서 security 설정을 진행할 수 있다.
public class SecurityConfig {

    // AuthenticationManager가 인자로 받을 AuthenticationConfiguration을 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    // 패스워드를 암호화할 수 있게 해주는 설정
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // addFilterAt()에서 LoginFilter를 추가하기 위해 Manager를 만들어주는 메서드
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf disable
        // 세션 방식에서는 세션이 고정되기 때문에 csrf 방어를 해줘야 함
        // jwt 방식은 stateless이기 때문에 disable
        http
                .csrf((auth) -> auth.disable());

        // form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        // 특정 경로에서는 어떤 권한을 가져야 하는가
        // http 인자에서
        http
                .authorizeHttpRequests((auth) -> auth
                        // 해당 경로는 허용
                        .requestMatchers("/login", "/", "/join").permitAll()
                        // 해당 경로는 ADMIN 권한 필요
                        .requestMatchers("/admin").hasRole("ADMIN")
                        // 그 외의 요청에 대해서는 로그인한 요청에 대해서만 허용
                        .anyRequest().authenticated());

        // LoginFilter 추가
        http
                // At = 해당 자리에 등록. Before, After도 있음
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil),
                        UsernamePasswordAuthenticationFilter.class);

        // JWTFilter 추가
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 세션 설정
        // jwt 방식에서는 세션은 stateless 방식으로 관리
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
