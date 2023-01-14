package com.yakbas.security.rest;

import com.yakbas.security.dto.LoginInfoDto;
import com.yakbas.security.service.JwtAuthService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class JwtLoginController {

    @Autowired
    JwtAuthService jwtAuthService;

    @GetMapping("/authenticate")
    public void authenticate(@RequestBody LoginInfoDto loginInfo, HttpServletResponse response) throws IOException {
        jwtAuthService.authenticate(loginInfo, response);
    }
}
