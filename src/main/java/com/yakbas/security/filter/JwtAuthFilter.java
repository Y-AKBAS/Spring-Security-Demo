package com.yakbas.security.filter;

import com.yakbas.security.auth.JwtAuthentication;
import com.yakbas.security.constants.JwtConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;


public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public JwtAuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(JwtConstants.AUTHORIZATION_HEADER_NAME);

        if (Objects.isNull(authHeader) || !authHeader.startsWith(JwtConstants.BEARER)) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = extractToken(authHeader);
        JwtAuthentication jwtAuthentication = JwtAuthentication.unauthenticated(token);

        try {
            if (Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
                final var authentication = (JwtAuthentication) authenticationManager.authenticate(jwtAuthentication);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContext newContext = SecurityContextHolder.createEmptyContext();
                newContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(newContext);
                filterChain.doFilter(request, response);
            }
        } catch (AuthenticationException e) {
            response.setCharacterEncoding("utf-8");
            response.setHeader("Content-type", "text/plain;charset=utf-8");
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().println(e.getMessage());
        }
    }


    private static String extractToken(final String authHeader) {
        return authHeader.substring(JwtConstants.BEARER.length() + 1);
    }
}
