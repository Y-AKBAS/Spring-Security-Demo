package com.yakbas.security.AuthProviders;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;

public class MyAdminAuthenticationProvider implements AuthenticationProvider {

    private static final String ADMIN_PRINCIPAL = "Yakbas";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (ADMIN_PRINCIPAL.equals(authentication.getName())) {
            return UsernamePasswordAuthenticationToken.authenticated(
                    ADMIN_PRINCIPAL,
                    null,
                    AuthorityUtils.createAuthorityList("ROLE_ADMIN")
            );
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
