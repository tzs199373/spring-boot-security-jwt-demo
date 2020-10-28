package com.security.controller;

import com.security.service.MethodService;
import com.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HelloController {
    @Autowired
    MethodService methodService;
    @Autowired
    UserService userService;

    @RequestMapping(value = "/login")
    public String login(@RequestParam String username,
                              @RequestParam String password) {
        String token = userService.login(username, password);
        if (token == null) {
            return "用户名或密码错误";
        }
        return token;
    }

    @GetMapping("/hello")
    public String hello() {
        return methodService.admin();
    }
    @GetMapping("/admin/hello")
    public String hello2(){
        return "admin";
    }
    @GetMapping("/db/hello")
    public String hello3(){
        return "db";
    }
    @GetMapping("/user/hello")
    public String hello4(){
        return "user";
    }
}
