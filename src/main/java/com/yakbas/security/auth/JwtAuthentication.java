package com.yakbas.security.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthentication extends UsernamePasswordAuthenticationToken {

    private final String token;

    private JwtAuthentication(Object principal, Object credentials, final String token) {
        super(principal, credentials);
        this.token = token;
    }

    private JwtAuthentication(Object principal, Object credentials,
                              Collection<? extends GrantedAuthority> authorities,
                              final String token) {
        super(principal, credentials, authorities);
        this.token = token;
    }


    public static JwtAuthentication unauthenticated(final String token) {
        return new JwtAuthentication(null, null, token);
    }

    public static JwtAuthentication authenticated(Object principal, Object credentials,
                                                  Collection<? extends GrantedAuthority> authorities) {
        return new JwtAuthentication(principal, credentials, authorities, null);
    }

    public String getToken() {
        return token;
    }
}
