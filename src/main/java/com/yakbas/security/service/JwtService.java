package com.yakbas.security.service;

import com.yakbas.security.config.ApplicationProperties;
import com.yakbas.security.constants.JwtConstants;
import com.yakbas.security.util.ObjectUtils;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static com.yakbas.security.constants.JwtConstants.AUTHORITIES;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    private final ApplicationProperties applicationProperties;

    @Autowired
    public JwtService(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
        logger.info("My very very secret secret is : {} :))", applicationProperties.getSecret());
    }

    public boolean isTokenValid(final String token) {
        try {
            getParsedClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            logger.warn("Jwt signature is invalid.");
        } catch (MalformedJwtException e) {
            logger.warn("Jwt token is invalid.");
        } catch (ExpiredJwtException e) {
            logger.info("Jwt token is expired.");
        } catch (UnsupportedJwtException e) {
            logger.warn("Jwt is unsupported.");
        } catch (IllegalArgumentException e) {
            logger.warn("Jwt token compact is invalid.");
        }

        return false;
    }

    public boolean isTokenExpired(final String token) {
        try {
            getParsedClaimsJws(token);
        } catch (ExpiredJwtException expiredJwtException) {
            return true;
        } catch (Exception ignored) {
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    public List<GrantedAuthority> getGrantedAuthorities(final String token) {
        final var jwtAuthorities =
                this.resolveClaim(token, claims -> claims.get(JwtConstants.AUTHORITIES, List.class));

        // Cleaner than streaming because of the casting stuff
        Set<String> authorities = new HashSet<>();
        for (final var obj : jwtAuthorities) {
            final var authoritiesMap = (Map<String, String>) obj;
            String authority = authoritiesMap.get(JwtConstants.AUTHORITY);

            if (!ObjectUtils.isEmpty(authority)) {
                authorities.add(authority);
            }
        }

        return AuthorityUtils.createAuthorityList(authorities.toArray(new String[0]));
    }

    public String resolveUserName(final String token) {
        String userName = resolveClaim(token, Claims::getSubject);
        if (ObjectUtils.isEmpty(userName)) {
            logger.error("Token without a subject cannot exist");
            throw new IllegalStateException();
        }
        return userName;
    }

    public boolean hasClaim(final String token, final String claim) {
        final var claims = resolveAllClaims(token);
        return Objects.nonNull(claims) && Objects.nonNull(claims.get(claim));
    }

    public <T> T resolveClaim(final String token, Function<Claims, T> claimResolver) {
        return claimResolver.apply(resolveAllClaims(token));
    }

    public Claims resolveAllClaims(final String token) {
        return getParsedClaimsJws(token).getBody();
    }

    private Jws<Claims> getParsedClaimsJws(String token) {
        return Jwts.parser().setSigningKey(applicationProperties.getSecret()).parseClaimsJws(token);
    }

    public String generateToken(String tenantId, UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtConstants.TENANT_ID, tenantId);
        claims.put(AUTHORITIES, userDetails.getAuthorities());
        return createToken(userDetails, claims);
    }

    private String createToken(UserDetails userDetails, Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(TimeUnit.HOURS.toMillis(12), ChronoUnit.MILLIS)))
                .signWith(SignatureAlgorithm.HS512, applicationProperties.getSecret())
                .compact();
    }
}
