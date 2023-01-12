package com.yakbas.security.filter;

import com.yakbas.security.auth.MyUserAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

//There is a AuthenticationFilter class. Check it too

//If you want to see all your filters put a break point in the FilterChainProxy.java
//where the additionalFilterChains are being set in the VirtualFilterChain constructor

//Apart from those security provides a very well trace level logging. You can enable it
//in your application.yml file to follow along what is being invoked in which order.

public class MyUserRequestFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(MyUserRequestFilter.class);

    private static final String HEADER_NAME = "user-pwd";

    private final AuthenticationManager authenticationManager;

    public MyUserRequestFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        logger.info("MyRequestFilter has been invoked");
        String headerPwd = request.getHeader(HEADER_NAME);

        if (Objects.isNull(headerPwd)) {
            filterChain.doFilter(request, response);
            return;
        }

        MyUserAuthentication authenticationReq = MyUserAuthentication.unauthenticated(headerPwd);

        try {
            Authentication authentication = authenticationManager.authenticate(authenticationReq);
            SecurityContext newContext = SecurityContextHolder.createEmptyContext();
            newContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(newContext);
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            response.setCharacterEncoding("utf-8");
            response.setHeader("Content-type", "text/plain;charset=utf-8");
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().println(e.getMessage());
        }
    }
}
