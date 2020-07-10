package tia.example.oauth2.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;

/**
 * Конвертер {@link Jwt} в {@link CmjBearerTokenAuthentication}.
 * Выполняется поиск пользователя в СО и проверка возможности входа в систему.<p/>
 * В качестве идентификатора пользователя используется {@link Jwt#getSubject()}.
 * Если пользователь не неайден, выполняется поиск по e-mail ({@link StandardClaimNames#EMAIL}).
 * Если найден по e-mail, то в карточку "Персона СО" записывается {@link Jwt#getSubject()} в таблицу альтернативных
 * идентификаторов.
 *
 * @since Spring Security 5.1
 */
public class CmjJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter
            = new JwtGrantedAuthoritiesConverter();

    private final UserDetailsService userDetailsService;

    public CmjJwtAuthenticationConverter(@NonNull UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
        this.userDetailsService = userDetailsService;
    }

    @Override
    public final AbstractAuthenticationToken convert(Jwt jwt) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof CmjBearerTokenAuthentication) {
            CmjBearerTokenAuthentication tokenAuthentication = (CmjBearerTokenAuthentication) authentication;
            //Сменил ли пользователь учётку.
            if (tokenAuthentication.getName().equals(jwt.getSubject())) {
                // Пользователь был сохранён в http-сесии. Не требуется повторная загрузка информации о нём из СО и доп.проверки
                OAuth2AccessToken accessToken = new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt());

                if (accessToken.equals(tokenAuthentication.getToken())) {
                    //Токен прежний, не обновлённый
                    return tokenAuthentication;
                } else {
                    //Токен пользователя обновлён. Сохраняем его.
                    CmUserDetailsLTPA principal = (CmUserDetailsLTPA) tokenAuthentication.getPrincipal();
                    return createAuthenticationToken(jwt, principal.getNotesName(), principal.getLtpaToken());
                }
            }
        }
        return onFirstLogin(jwt);
    }

    protected AbstractAuthenticationToken onFirstLogin(Jwt jwt) {

        // TODO use jwt.getSubject()
        String userId = jwt.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME);

        UserDetails userDetails = userDetailsService.loadUserByUsername(userId);
        Boolean isVerified = jwt.getClaimAsBoolean(StandardClaimNames.EMAIL_VERIFIED);
        if (userDetails == null && Boolean.TRUE.equals(isVerified)) {
            String email = jwt.getClaimAsString(StandardClaimNames.EMAIL);
            // TODO реализовать
            //userDetails = userDetailsService.loadUserByEMail(email);
            if (userDetails != null) {
                // TODO реализовать
                //userDetailsService.saveOauth2UserId(jwt.getSubject(), userDetails);
            }
        }
        if (userDetails == null) {
            BearerTokenError error = BearerTokenErrors.invalidRequest("User is not found");
            throw new OAuth2AuthenticationException(error);
        }
        String ltpaToken = null;
        // TODO реализовать
        //ltpaToken = ltpaService.generateLtpaToken(userDetails.getUsername());

        return createAuthenticationToken(jwt, userDetails.getUsername(), ltpaToken);
    }

    private AbstractAuthenticationToken createAuthenticationToken(Jwt jwt, String notesName, String ltpaToken) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt());
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        Map<String, Object> attributes = jwt.getClaims();
        CmUserDetailsLTPA principal = new CmUserDetailsLTPA(jwt.getSubject(), notesName, ltpaToken, attributes, authorities);
        return new CmjBearerTokenAuthentication(principal, accessToken);
    }

    /**
     * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a {@link Jwt}
     *
     * @param jwt The token
     * @return The collection of {@link GrantedAuthority}s found on the token
     * @see JwtGrantedAuthoritiesConverter
     * @see #setJwtGrantedAuthoritiesConverter(Converter)
     */
    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        return this.jwtGrantedAuthoritiesConverter.convert(jwt);
    }

    /**
     * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;} to use.
     * Defaults to {@link JwtGrantedAuthoritiesConverter}.
     *
     * @param jwtGrantedAuthoritiesConverter The converter
     * @see JwtGrantedAuthoritiesConverter
     * @since 5.2
     */
    public void setJwtGrantedAuthoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
        Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
    }

}
