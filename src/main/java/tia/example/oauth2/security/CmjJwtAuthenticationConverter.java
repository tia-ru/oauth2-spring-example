package tia.example.oauth2.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * Конвертер {@link Jwt} в {@link CmjJwtAuthenticationToken}
 * @since Spring Security 5.1
 */
public class CmjJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter
            = new JwtGrantedAuthoritiesConverter();

    private final UserDetailsService userDetailsService;

    public CmjJwtAuthenticationConverter(@NonNull UserDetailsService userDetailsService){
        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
        this.userDetailsService = userDetailsService;
    }
    @Override
    public final AbstractAuthenticationToken convert(Jwt jwt) {
        String user = jwt.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME); // TODO use jwt.getSubject()

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof CmjJwtAuthenticationToken) {
            CmjJwtAuthenticationToken tokenAuthentication = (CmjJwtAuthenticationToken) authentication;
            if (tokenAuthentication.getName().equals(user)){
                // Пользователь был сохранён в http-сесии. Не требуется повторная загрузка информации о нём из СО и доп.проверки
                if (jwt.equals(tokenAuthentication.getToken())){
                    //Токен прежний, не обновлённый
                    return tokenAuthentication;
                } else {
                    //Токен обновлён.
                    Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
                    return new CmjJwtAuthenticationToken(jwt, tokenAuthentication.getPrincipal(), authorities);
                }
            }
        }
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        UserDetails userDetails = userDetailsService.loadUserByUsername(user);
        if (userDetails == null){
            String email = jwt.getClaimAsString(StandardClaimNames.EMAIL_VERIFIED);
            // TODO реализовать
            //userDetails = userDetailsService.loadUserByEMail(email);
            if (userDetails == null){
                throw new UsernameNotFoundException(user);
            }
            // TODO реализовать
            //userDetailsService.saveOauth2UserId(jwt.getSubject(), userDetails);
        }
        CmUserDetailsLTPA cmUserDetails = new CmUserDetailsLTPA(userDetails.getUsername(),"", authorities);
        return new CmjJwtAuthenticationToken(jwt, cmUserDetails, authorities);
    }

    /**
     * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a {@link Jwt}
     *
     * @param jwt The token
     * @return The collection of {@link GrantedAuthority}s found on the token
     * @deprecated Since 5.2. Use your own custom converter instead
     * @see JwtGrantedAuthoritiesConverter
     * @see #setJwtGrantedAuthoritiesConverter(Converter)
     */
    @Deprecated
    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        return this.jwtGrantedAuthoritiesConverter.convert(jwt);
    }

    /**
     * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;} to use.
     * Defaults to {@link JwtGrantedAuthoritiesConverter}.
     *
     * @param jwtGrantedAuthoritiesConverter The converter
     * @since 5.2
     * @see JwtGrantedAuthoritiesConverter
     */
    public void setJwtGrantedAuthoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
        Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
    }
}
