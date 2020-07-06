package tia.example.oauth2.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import java.util.Collection;
import java.util.Map;


/**
 * An implementation of an {@link AbstractOAuth2TokenAuthenticationToken}
 * representing a {@link Jwt} {@code Authentication}.
 *
 * Реализация идентична {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken},
 * но без аннотации {@code @Transient}, что позволяет сохранять токен в http-сессии.
 *
 * @since Spring Security 5.1
 */
public final class CmjJwtAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String name;

    /**
     * Constructs a {@code CmjJwtAuthenticationToken} using the provided parameters.
     *
     * @param jwt the JWT
     * @param principal экземпляр CmUserDetailsLTPA
     * @param authorities the authorities assigned to the JWT
     */
    public CmjJwtAuthenticationToken(Jwt jwt, User principal, Collection<? extends GrantedAuthority> authorities) {
        super(jwt, principal, jwt, authorities);
        this.setAuthenticated(true);
        this.name = principal.getUsername();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getTokenAttributes() {
        return this.getToken().getClaims();
    }

    /**
     * The principal name which is, by default, the {@link Jwt}'s subject
     */
    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public User getPrincipal() {
        return (User) super.getPrincipal();
    }
}
