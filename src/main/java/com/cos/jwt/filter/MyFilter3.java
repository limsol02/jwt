package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        // 한글 요청
        req.setCharacterEncoding("UTF-8");
        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("필터3 헤더"+headerAuth);
            /*
            토큰 : 현재는 cos라고 강제로 집어 넣었지만, 이걸 만들어 줘야한다.
            생성시기? id & password 가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
            요청할 때마다 header에 Authorization 의 value값으로 토큰을 가지고 오게 될텐데,
            그때 토큰이 넘어오면 이 토큰이 내가 생성한 토큰이 맞는지 검증하면 된다.
            * */
            if(headerAuth != null ){
                System.out.println("호출된 헤더 : "+headerAuth);
                chain.doFilter(req, res);
            }else{
                PrintWriter writer = res.getWriter();
                System.out.println("인증 안됨");
            }

        }
    }

}
