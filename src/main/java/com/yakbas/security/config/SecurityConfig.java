package com.yakbas.security.config;

import com.yakbas.security.AuthProviders.MyAdminAuthenticationProvider;
import com.yakbas.security.AuthProviders.OAuth2LimitingAuthenticationProvider;
import com.yakbas.security.PostProcessor.OAuth2LimitingAuthenticationProviderPostProcessor;
import com.yakbas.security.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    JwtService jwtService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationEventPublisher eventPublisher) {
        try {
            http.getSharedObject(AuthenticationManagerBuilder.class)
                    .authenticationEventPublisher(eventPublisher); // Helps to publish events

            return http.csrf().disable()
                    .authorizeHttpRequests(
                            requestConfig -> {
                                requestConfig.requestMatchers("/").permitAll();
                                requestConfig.requestMatchers("/authenticate").permitAll();
                                requestConfig.requestMatchers("/error").permitAll();
                                requestConfig.requestMatchers("/favicon.ico").permitAll();
                                requestConfig.anyRequest().authenticated();
                            }
                    ).formLogin(Customizer.withDefaults())
                    .authenticationProvider(new MyAdminAuthenticationProvider())
                    //.oauth2Login(Customizer.withDefaults()) // we tell spring to use this too.
                    //.oauth2Login(getOAuth2LoginConfigurerCustomizer()) // with post processor 1. variant
                    .oauth2Login().withObjectPostProcessor(
                            new OAuth2LimitingAuthenticationProviderPostProcessor<>(OAuth2LoginAuthenticationProvider.class)
                    ).and() // // with post processor 2. variant
                    .apply(new MyUserLoginConfigurer()).and() // Here goes all the user related stuff.
                    .apply(new JwtLoginConfigurer(jwtService)).and() // Here goes the jwt related stuff

                    /*
                    if you want to just use jwt, activate this line. Otherwise, do not do that :)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                     */

                    .build();
        } catch (Exception e) {
            logger.error("Security config failed. Error message: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password("{noop}password")
                        .authorities("ROLE_USER")
                        .build(),
                User.builder()
                        .username("yasin")
                        .password("{noop}password")
                        .authorities("ROLE_ADMIN", "ROLE_USER")
                        .build()
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return null;
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return false;
            }
        };
    }

    @Bean
    public ApplicationListener<AuthenticationSuccessEvent> authenticationSuccessEvent() {
        return event -> logger.info("Successful Authentication! \nAuthenticationProvider: {} \nUser: {}",
                event.getAuthentication().getClass().getSimpleName(),
                event.getAuthentication().getName());
    }

    @Bean
    ApplicationListener<AuthenticationFailureBadCredentialsEvent> badCredentialsEvent() {
        return event -> logger.info("Bad Credentials! \nAuthenticationProvider: {} \nUser: {}",
                event.getAuthentication().getClass().getSimpleName(),
                event.getAuthentication().getName());
    }

    private static Customizer<OAuth2LoginConfigurer<HttpSecurity>> getOAuth2LoginConfigurerCustomizer() {
        return oAuth2config -> oAuth2config.withObjectPostProcessor(
                new ObjectPostProcessor<AuthenticationProvider>() {
                    @Override
                    public <O extends AuthenticationProvider> O postProcess(O object) {
                        return (O) new OAuth2LimitingAuthenticationProvider(object);
                    }
                }
        );
    }
}
