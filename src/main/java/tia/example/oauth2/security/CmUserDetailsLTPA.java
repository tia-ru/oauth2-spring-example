package tia.example.oauth2.security;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static org.springframework.security.core.authority.AuthorityUtils.NO_AUTHORITIES;

//public class CmUserDetailsLTPA extends User implements JwtClaimAccessor {
public class CmUserDetailsLTPA implements AuthenticatedPrincipal, JwtClaimAccessor, Serializable {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private String notesName;
    private final String ltpaToken;
    private final Map<String, Object> attributes;
    private final Collection<GrantedAuthority> authorities;
    private final String name;

    public CmUserDetailsLTPA(String name, String notesName, String ltpaToken, Map<String, Object> attributes, Collection<? extends GrantedAuthority> authorities) {
        this.notesName = notesName;
        //super(username, "", authorities);

        this.ltpaToken = ltpaToken;
        this.attributes = Collections.unmodifiableMap(attributes);
        this.authorities = authorities == null ?
                NO_AUTHORITIES : Collections.unmodifiableCollection(authorities);
        this.name = name == null ? (String) this.attributes.get(StandardClaimNames.SUB) : name;
    }


    @Override
    public Map<String, Object> getClaims() {
        return attributes;
    }

    /**
     * {@inheritDoc}
     * Представляет собой идентификатор учётной записи пользователя в IDP, переданном в токене в клайме 'sub'.
     */
    @Override
    public String getName() {
        return this.name;
    }

    /**
     * Системное имя пользователя
     * @return системное имя
     */
    public String getNotesName() {
        return notesName;
    }

    public String getLtpaToken() {
        return ltpaToken;
    }

    /**
     * Get the {@link Collection} of {@link GrantedAuthority}s associated
     * with this OAuth 2.0 token
     *
     * @return the OAuth 2.0 token authorities
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        CmUserDetailsLTPA that = (CmUserDetailsLTPA) obj;

        if (!this.getName().equals(that.getName())) {
            return false;
        }
        if (!this.getAuthorities().equals(that.getAuthorities())) {
            return false;
        }
        return this.getClaims().equals(that.getClaims());
    }

    @Override
    public int hashCode() {
        int result = this.getName().hashCode();
        result = 31 * result + this.getAuthorities().hashCode();
        result = 31 * result + this.getClaims().hashCode();
        return result;
    }

    @Override
    public String toString() {
        String sb = "Name: [" +
                this.getNotesName() +
                "], Granted Authorities: [" +
                getAuthorities() +
                "], User Attributes: [" +
                getClaims() +
                "]";
        return sb;
    }
}
