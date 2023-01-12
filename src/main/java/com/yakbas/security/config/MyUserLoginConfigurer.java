package com.yakbas.security.config;

import com.yakbas.security.AuthProviders.MyUserAuthenticationProvider;
import com.yakbas.security.filter.MyUserRequestFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class MyUserLoginConfigurer extends AbstractHttpConfigurer<MyUserLoginConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        // Put your authenticationProviders here
        http.authenticationProvider(new MyUserAuthenticationProvider());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // Put your filters here
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        http.addFilterBefore(new MyUserRequestFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
    }
}
