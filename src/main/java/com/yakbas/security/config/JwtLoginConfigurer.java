package com.yakbas.security.config;

import com.yakbas.security.AuthProviders.JwtAuthenticationProvider;
import com.yakbas.security.filter.JwtAuthFilter;
import com.yakbas.security.service.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtLoginConfigurer extends AbstractHttpConfigurer<JwtLoginConfigurer, HttpSecurity> {

    private final JwtService jwtService;

    public JwtLoginConfigurer(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        // here comes the authentication provider
        http.authenticationProvider(new JwtAuthenticationProvider(jwtService));
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // here comes the filter
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        http.addFilterBefore(new JwtAuthFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
    }
}
