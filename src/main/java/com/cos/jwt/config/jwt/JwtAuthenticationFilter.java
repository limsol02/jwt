package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

/*
스프링 시큐리티의 UsernamePasswordAuthenticationFilter 필터가 기존에 존재하는데,
login 요청해서 username, password 를 전송하면 UsernamePasswordAuthenticationFilter 가 동작을 한다.

JwtAuthenticationFilter 를 새로 만들어 securityConfig 에 새로 등록을 한다. => .addFilter(new JwtAuthenticationFilter(authenticationManager))
*/

/*
       1) 로그인 요청 시 username, password 를 받아서
       2) 정상인지 로그인 시도
       3) authenticationManager로 로그인 시도를 하면 PrincipalDetailsService 호출
       4) PrincipalDetailsService의 loadUserByUsername 자동으로 실행
       5) loadUserByUsername의 리턴값인 PrincipalDetail 가 호출되면
       6) PrincipalDetail를 세션에 담고 => 담는이유? 시큐리티가 권한관리를 위해, 만약 권한이 필요없다면 굳이 세션에 담을 필요 없음.
       7) JWT 토큰을 만들어서 응답해주는 과정
       * */
@RequiredArgsConstructor
// 로그인 시도를 하면 UsernamePasswordAuthenticationFilter 가 낚아채서 attemptAuthentication함수가 자동으로 실행
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인시도중");
        try {
           /* BufferedReader br = request.getReader();
            String input = null;
            while((input = br.readLine())!=null){
                // username=sol2&password=1111 => x-www-form-urle 어쩌고형식..
                // JSON으로 보내면 알아서 json 형태로 뜸
                System.out.println(input);
            }
            // org.apache.catalina.connector.CoyoteInputStream@7d4637d9 안에 내 이름이랑 비밀번호가 담겨있음 신기하네
            System.out.println(request.getInputStream().toString()); // org.apache.catalina.connector.CoyoteInputStream@7d4637d9*/
            // 위 방식 말고 json 으로 보내면 훨씬 쉽게 처리할 수 있다.
            ObjectMapper mapper = new ObjectMapper(); // json parsing 객체
            User user = mapper.readValue(request.getReader(), User.class);
            // 토큰 생성
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            // PrincipalDetailsService 의 loadUserByUsername() 함수 실행
            // Authentication에 authRequest(토큰) 을 넣어서 던지면 인증을 해주는 방식 => Authentication에 내 정보가 담김
            // DB에 있는 username과 password가 일치한다.
            Authentication auth = authenticationManager.authenticate(authRequest);

            // 정보 꺼내기 =>  로그인(DB 토대)
            PrincipalDetails principalDetails = (PrincipalDetails)auth.getPrincipal();
            // 출력을 통해 정상적으로 로그인 여부 확인
            // Authentication 객체가 session 영역에 저장됨(return 방법을 통하여)
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는것 뿐
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만, 단순히 권한 처리로 인해 세션을 넣어줌
            return auth;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    //attemptAuthentication 함수에서 인증이 정상적으로 처리되고 종료되면 실행되는 함수 이쪽에서 JWT 토큰 발행
    // JWT 토큰을 발행한 후 request요청한 사용자에게 JWT토큰을 전달해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 메서드 호출됨");
        PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
        // principalDetails 이 정보를 통해 JWT 토큰 발행
        // RSA 방식 아니고 Hash 암호방식
        System.out.println("jwtToken 생성 이전");
        String jwtToken = JWT.create()
                .withSubject("cos토큰") // 토큰 이름=> 큰의미 없음
                // 토큰 만료시간 new Date(System.currentTimeMillis() = 현재시간 + (60000)*10 10분
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*10))
                // 내가 넣고 싶은 정보 암거나 넣어도됨~
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC256("cos")); // secret key

        response.addHeader("Authorization","Bearer "+jwtToken);
        System.out.println("jwtToken 생성 완료");
        System.out.println(response.getHeaderNames()+":"+response.getHeader("Authorization"));
        System.out.println("헤더 add");
        super.successfulAuthentication(request, response, chain, authResult);
        System.out.println("super.successfulAuthentication 완료");
    }
}
