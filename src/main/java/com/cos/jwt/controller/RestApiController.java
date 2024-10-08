package com.cos.jwt.controller;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {

    private final UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public RestApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("home")
    public String home(){
        return "<h1>HOME</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("USER");
        userRepository.save(user);
        return "회원가입 완료!";
    }
    // user+manager+admin 접근가능
    @PostMapping("/api/v1/user")
    public String user(){
        return "user";
    }
    // manager+admin 접근가능
    @PostMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }
    // admin 접근가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }
}
