package com.cos.jwt.config;


import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity // 시큐리티 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // HttpSecurity를 통해 AuthenticationManager 가져오기
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManagerBuilder.class).build();
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager);
        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(authenticationManager,userRepository);

        http
                // 만약 제~~일 먼저 실행하고싶으면 BasicAuthenticationFilter.class 말고 현재꺼 적어주면됨(필터중에 제일 먼저 실행되는 내장 클래스)  BasicAuthenticationFilter.class
                .addFilterAfter(new MyFilter3(), SecurityContextPersistenceFilter.class) // 따로 만든 FilterConfig 보다 무조건 먼저 실행
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ) // 세션을 사용하지 않는다
                .addFilter(corsFilter) // @CrossOrigin는 인증이 없을때 사용, addFilter는 인증이 있을때 사용
                .formLogin(formLogin -> formLogin.disable()) // form tag 를 이용한 로그인 사용 안함
                .httpBasic(httpBasic -> httpBasic.disable()) // 기존 인증방식이 아닌 우리가 쓸꺼는 authorization에 토큰을 들고가는 베리어 방식을 사용할 예정
                .authenticationManager(authenticationManager)
                .addFilter(jwtAuthenticationFilter) // 꼭 필요한 parameter = AuthenticationManager, 기존에는 바로 넣어서 쓸수있었는데
                // 스프링 업데이트 되면서 바로 들고오는건 못하고 상단의 코드처럼 따로 가지고 와야 쓸수있다.
                .addFilter(jwtAuthorizationFilter)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/api/v1/user")
                                .hasAnyAuthority("USER", "MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/manager/**")
                                .hasAnyAuthority("MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/admin/**")
                                .hasAuthority("ADMIN")
                                .anyRequest().permitAll()
                );

        return http.build();
    }
}
