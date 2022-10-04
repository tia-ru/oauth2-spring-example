package tia.example.oauth2.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class RequestHeaderAuthenticationManager implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication.getClass())){
            return null;
        }
        PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) authentication;
        token.setAuthenticated(true);
        return token;
    }
}
