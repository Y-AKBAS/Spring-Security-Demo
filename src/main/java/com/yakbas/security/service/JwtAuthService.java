package com.yakbas.security.service;

import com.yakbas.security.constants.JwtConstants;
import com.yakbas.security.dto.LoginInfoDto;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class JwtAuthService {

    @Autowired
    UserDetailsService userDetailsService;
    @Autowired
    JwtService jwtService;

    public void authenticate(final LoginInfoDto loginInfoDto, HttpServletResponse response) throws IOException {
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginInfoDto.getUserName());

        if (userDetails.getPassword().equals(loginInfoDto.getPassword())) {
            String token = jwtService.generateToken(JwtConstants.TENANT_ID, userDetails);
            /*Cookie cookie = new Cookie(
                    JwtConstants.AUTHORIZATION_HEADER_NAME,
                    JwtConstants.BEARER + " " + token
            );
            response.addCookie(cookie);*/
            response.addHeader(
                    JwtConstants.AUTHORIZATION_HEADER_NAME,
                    JwtConstants.BEARER + " " + token
            );
            return;
        }

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().println("Wrong username/password. Please try again!");
    }
}
