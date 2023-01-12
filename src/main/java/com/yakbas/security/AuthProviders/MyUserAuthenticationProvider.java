package com.yakbas.security.AuthProviders;

import com.yakbas.security.auth.MyUserAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class MyUserAuthenticationProvider implements AuthenticationProvider {

    private static final String PWD = "expectedPwd";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MyUserAuthentication myUserAuthentication = (MyUserAuthentication) authentication;

        if (PWD.equals(myUserAuthentication.getPassword())) {
            return MyUserAuthentication.authenticated();
        }

        throw new BadCredentialsException("Wrong username/password. Please try again😎");

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MyUserAuthentication.class.isAssignableFrom(authentication);
    }
}
