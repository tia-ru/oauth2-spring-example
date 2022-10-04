package tia.example.oauth2.security;

import java.time.Instant;
import java.util.Collection;
import java.util.function.BiFunction;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

/**
 * An {@link AuthenticationProvider} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s,
 * using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
 * to check the token's validity and reveal its attributes.
 * <p>
 * This {@link AuthenticationProvider} is responsible for introspecting and verifying an opaque access token,
 * returning its attributes set as part of the {@link Authentication} statement.
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following algorithm:
 * <ol>
 * <li>
 * If there is a "scope" attribute, then convert to a {@link Collection} of {@link String}s.
 * <li>
 * Take the resulting {@link Collection} and prepend the "SCOPE_" keyword to each element, adding as {@link GrantedAuthority}s.
 * </ol>
 *
 * @author Josh Cummings
 * @since 5.2
 * @see AuthenticationProvider
 */
public final class CmjOpaqueTokenAuthenticationProvider implements AuthenticationProvider {
    private final boolean useStoredAuthentication;
    private OpaqueTokenIntrospector introspector;
    private BiFunction<OAuth2AuthenticatedPrincipal, String, AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token>> authenticationConverter = new DefaultAuthenticationConverter();

    /**
     * Creates a {@code OpaqueTokenAuthenticationProvider} with the provided parameters
     *
     * @param introspector The {@link OpaqueTokenIntrospector} to use
     */
    public CmjOpaqueTokenAuthenticationProvider(OpaqueTokenIntrospector introspector) {
        this(introspector, true);
    }
    public CmjOpaqueTokenAuthenticationProvider(OpaqueTokenIntrospector introspector, boolean useStoredAuthentication) {
        Assert.notNull(introspector, "introspector cannot be null");
        this.useStoredAuthentication = useStoredAuthentication;
        this.introspector = introspector;
    }

    /**
     * Introspect and validate the opaque
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
     *
     * @param authentication the authentication request object.
     *
     * @return A successful authentication
     * @throws AuthenticationException if authentication failed for some reason
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!(authentication instanceof BearerTokenAuthenticationToken)) {
            return null;
        }

        BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
        Authentication storedAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (checkStoredAuthentication(storedAuthentication, bearer)) {
            return storedAuthentication;
        } else {
            return doIntrospection(bearer);
        }
    }

    private AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token> doIntrospection(BearerTokenAuthenticationToken bearer) {

        OAuth2AuthenticatedPrincipal principal;
        AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token> result;
        try {
            principal = this.introspector.introspect(bearer.getToken());
            if (principal == null || principal.getName() == null) {
                throw new InvalidBearerTokenException("Token introspection response has not 'sub' claim");
            }
            result = authenticationConverter.apply(principal, bearer.getToken());
            result.setDetails(bearer.getDetails());
        } catch (BadOpaqueTokenException failed) {
            throw new InvalidBearerTokenException(failed.getMessage());
        } catch (OAuth2IntrospectionException failed) {
            throw new AuthenticationServiceException(failed.getMessage());
        }
        return result;
    }

    private boolean checkStoredAuthentication(Authentication storedAuthentication, BearerTokenAuthenticationToken bearer) {
        if (useStoredAuthentication && storedAuthentication instanceof AbstractOAuth2TokenAuthenticationToken) {
            AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token> tokenAuthentication =
                    (AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token>) storedAuthentication;
            AbstractOAuth2Token storedBearer = tokenAuthentication.getToken();
            if (storedBearer != null) {
                return bearer.getToken().equals(storedBearer.getTokenValue()) &&
                        // Для случая если storedBearer.getExpiresAt() не взят из токена, а вычислен эмпирически
                        // и срок токена истёк, то делаем интроспекцию
                        (storedBearer.getExpiresAt() == null || storedBearer.getExpiresAt().isAfter(Instant.now()));
            }
        }
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthenticationConverter(
            @NonNull
            BiFunction<OAuth2AuthenticatedPrincipal, String, AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token>>
            opaqueAuthenticationConverter)
    {

        Assert.notNull(opaqueAuthenticationConverter, "opaqueAuthenticationConverter cannot be null");
        this.authenticationConverter = opaqueAuthenticationConverter;
    }

    static class DefaultAuthenticationConverter implements BiFunction<OAuth2AuthenticatedPrincipal, String, AbstractOAuth2TokenAuthenticationToken<?>> {
        @Override
        public AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token> apply(OAuth2AuthenticatedPrincipal principal, String token) {
            Instant iat = principal.getAttribute(ISSUED_AT);
            if (iat == null) {
                iat = Instant.now();
            }
            Instant exp = principal.getAttribute(EXPIRES_AT);
            if (exp == null) {
                //TODO
                //final Integer sessionMaxAge = env.getProperty("cmj.auth.max-age.cmjsid.cookie", Integer.class, CMJ_JSESSION_COOKIE_DEFAULT_MAXAGE);
                int sessionMaxAge = 3600;
                exp = iat.plusSeconds(sessionMaxAge);
            }

            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, iat, exp);
            //TODO
            CmUserDetailsLTPA ltpa = new CmUserDetailsLTPA(principal.getName(), principal.getName(), null, principal.getAttributes(), principal.getAuthorities());
            AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token> t = new CmjBearerTokenAuthentication(ltpa, accessToken);
            return new CmjBearerTokenAuthentication(ltpa, accessToken);
        }
    }
}
