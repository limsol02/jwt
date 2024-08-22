package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

/*
Security가 filter를 가지고 있는데 그 filter 중에 BasicAuthenticationFilter라는 것이 있다.
권한이나 인증에 필요한 특정 주소를 요청했을때, 위 필터를 무조건 거치게 되어있다.
만약, 권한이나 인증이 필요한 주소가 아니라면 위 필터는 거치치 않는다.
* */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
       //super.doFilterInternal(request, response, chain);
        System.out.println("권한이나 인증이 필요한 메뉴입니다.");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : "+jwtHeader);

        // header가 있는지 확인
        if(jwtHeader == null || !(jwtHeader.startsWith("Bearer "))) {
            chain.doFilter(request, response);
            return;
        }
        // JWT 토큰을 검증을 해서 정상적인 사용자 인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        System.out.println("token : "+jwtToken);
        // 서명이 정상적이라면, username을 들고옴
        String username = JWT.require(Algorithm.HMAC256("cos")).build().verify(jwtToken).getClaim("username").asString();
        if(username!=null){
            System.out.println("username 정상");
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            // 매개변수는 principalDetails,password 입력 + 권한
            // JWT 토큰 서명을 통해서 서명이 정상이면, authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            System.out.println("authentication:"+authentication);
            SecurityContextHolder.getContext().setAuthentication(authentication); // 시큐리티 세션 저장공간을 찾아서 authentication 객체를 저장

            chain.doFilter(request, response);

        }
    }
}
