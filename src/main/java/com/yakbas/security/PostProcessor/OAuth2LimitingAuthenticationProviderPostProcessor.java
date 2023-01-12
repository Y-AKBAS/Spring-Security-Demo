package com.yakbas.security.PostProcessor;

import com.yakbas.security.AuthProviders.OAuth2LimitingAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;

public class OAuth2LimitingAuthenticationProviderPostProcessor<T extends AuthenticationProvider>
        implements ObjectPostProcessor<T> {

    private final Class<T> tClass;
    private static final Logger logger = LoggerFactory.getLogger(OAuth2LimitingAuthenticationProviderPostProcessor.class);

    public OAuth2LimitingAuthenticationProviderPostProcessor(Class<T> tClass) {
        this.tClass = tClass;
    }

    @Override
    public <O extends T> O postProcess(O object) {
        if (tClass.isAssignableFrom(object.getClass())) {
            return (O) new OAuth2LimitingAuthenticationProvider(object);
        }
        logger.warn("{} Class couldn't be casted successfully",
                OAuth2LimitingAuthenticationProviderPostProcessor.class.getSimpleName());
        return object;
    }
}
