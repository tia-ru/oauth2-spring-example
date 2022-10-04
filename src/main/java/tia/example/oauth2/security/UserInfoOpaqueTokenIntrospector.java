package tia.example.oauth2.security;

import java.time.Instant;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

public class UserInfoOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    private final OpaqueTokenIntrospector delegate;
    private final OAuth2UserService oauth2UserService = new DefaultOAuth2UserService();

    private final ClientRegistration clientRegistration;


    public UserInfoOpaqueTokenIntrospector(OpaqueTokenIntrospector delegate, ClientRegistration clientRegistration) {
        this.delegate = delegate;
        this.clientRegistration = clientRegistration;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
        if (principal.getName() != null) {
            return principal;
        }

        Instant issuedAt = principal.getAttribute(ISSUED_AT);
        Instant expiresAt = principal.getAttribute(EXPIRES_AT);
        OAuth2AccessToken accToken = new OAuth2AccessToken(TokenType.BEARER, token, issuedAt, expiresAt);
        OAuth2UserRequest oauth2UserRequest = new OAuth2UserRequest(clientRegistration, accToken);
        OAuth2User user = this.oauth2UserService.loadUser(oauth2UserRequest);
        return user;
    }
}