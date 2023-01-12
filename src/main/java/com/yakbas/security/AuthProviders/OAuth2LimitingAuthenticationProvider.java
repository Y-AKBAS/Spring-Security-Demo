package com.yakbas.security.AuthProviders;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class OAuth2LimitingAuthenticationProvider implements AuthenticationProvider {

    private static final Map<String, Instant> LOGIN_CACHE = new ConcurrentHashMap<>();
    private final AuthenticationProvider authenticationProvider;

    public OAuth2LimitingAuthenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication authResult = authenticationProvider.authenticate(authentication);

        if (Objects.isNull(authResult)) {
            return null;
        }

        if (isUpdateCache(authResult)) {
            return authResult;
        }

        throw new AuthenticationException("Too many login attempts!\nTry after 30 secs again!") {
        };
    }

    private static boolean isUpdateCache(Authentication authResult) {
        var now = Instant.now();
        var previousAttemptTime = LOGIN_CACHE.get(authResult.getName());
        LOGIN_CACHE.put(authResult.getName(), now);
        return Objects.isNull(previousAttemptTime) || previousAttemptTime.plus(Duration.ofSeconds(30)).isBefore(now);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authenticationProvider.supports(authentication);
    }
}
