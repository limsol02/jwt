package com.cos.jwt.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // autoincre
    private long id;
    private String username;
    private String password;
    private String roles; // USER, ADMIN... 다중 권한 ㅇ
    public User() {
    }
    // 다중 권한을 위한 메서드 생성
    public List<String> getRoleList(){
        if(this.roles.length()>0){
            return Arrays.asList(this.roles.split(","));
        }else{
            return new ArrayList<>();
        }
    }

}
