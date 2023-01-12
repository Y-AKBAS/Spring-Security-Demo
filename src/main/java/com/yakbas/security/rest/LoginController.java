package com.yakbas.security.rest;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class LoginController {

    @GetMapping("/")
    public String getStartPageMessage() {
        return "Welcome to Security Demo";
    }

    @GetMapping("/private")
    public String checkLogin(Authentication authentication) { // Authentication can be injected this way
        return "This can be seen just by logged in users 👌" +
                "Welcome " + getAuthenticationName(authentication) + "!";
    }

    @GetMapping("private/context")
    public String checkContext() { // Authentication can be extracted this way
        final var auth = SecurityContextHolder.getContext().getAuthentication();
        return "User: " + getAuthenticationName(auth) + " extracted from context";
    }

    private static String getAuthenticationName(Authentication authentication) {
        return Optional.ofNullable(authentication.getPrincipal())
                .filter(DefaultOAuth2User.class::isInstance)
                .map(DefaultOAuth2User.class::cast)
                .map(p -> p.getAttribute("login"))
                .map(String.class::cast)
                .orElse("");
    }

}
