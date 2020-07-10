package tia.example.oauth2.security;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;


/**
 * An implementation of an {@link AbstractOAuth2TokenAuthenticationToken}
 * representing a {@link Jwt} {@code Authentication}.
 *
 * Реализация идентична {@link org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication}
 * но без аннотации {@code @Transient}, что позволяет сохранять токен в http-сессии.
 *
 * @since Spring Security 5.1
 */
public final class CmjBearerTokenAuthentication extends AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken> {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private Map<String, Object> attributes;

    /**
     * Constructs a {@link BearerTokenAuthentication} with the provided arguments
     *  @param principal The OAuth 2.0 attributes
     * @param credentials The verified token
     */
    public CmjBearerTokenAuthentication(CmUserDetailsLTPA principal, OAuth2AccessToken credentials) {

        super(credentials, principal, credentials, principal.getAuthorities());
        Assert.isTrue(credentials.getTokenType() == OAuth2AccessToken.TokenType.BEARER, "credentials must be a bearer token");
        this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(principal.getClaims()));
        setAuthenticated(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getTokenAttributes() {
        return this.attributes;
    }
}
