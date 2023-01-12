package com.yakbas.security.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class MyUserAuthentication implements Authentication {
    private final boolean isAuthenticated;
    private final List<GrantedAuthority> authorityList;

    private final String password;

    private MyUserAuthentication(List<GrantedAuthority> authorityList, String password) {
        this.authorityList = authorityList;
        this.password = password;
        this.isAuthenticated = Objects.isNull(password);
    }

    public static MyUserAuthentication authenticated() {
        return new MyUserAuthentication(AuthorityUtils.createAuthorityList("ROLE_USER"), null);
    }

    public static MyUserAuthentication unauthenticated(final String password) {
        return new MyUserAuthentication(Collections.emptyList(), password);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorityList;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return "MyPrincipal";
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        throw new IllegalArgumentException();
    }

    @Override
    public String getName() {
        return "MyPrincipal Name";
    }

    public String getPassword() {
        return password;
    }
}
