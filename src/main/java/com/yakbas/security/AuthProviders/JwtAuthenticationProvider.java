package com.yakbas.security.AuthProviders;

import com.yakbas.security.auth.JwtAuthentication;
import com.yakbas.security.constants.JwtConstants;
import com.yakbas.security.service.JwtService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.util.Collection;
import java.util.List;
import java.util.Map;


public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtService jwtService;

    public JwtAuthenticationProvider(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final JwtAuthentication jwtAuthentication = (JwtAuthentication) authentication;
        final String token = jwtAuthentication.getToken();

        if (jwtService.isTokenValid(token)) {
            final String userName = jwtService.resolveUserName(token);
            return JwtAuthentication.authenticated(
                    userName,
                    null,
                    jwtService.getGrantedAuthorities(token)
            );
        }

        throw new AuthenticationException("Please login again!") {
        };
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }
}
