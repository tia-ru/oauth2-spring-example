package tia.example.oauth2.security;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.StringUtils;

import static org.springframework.security.oauth2.server.resource.BearerTokenErrors.invalidRequest;
import static org.springframework.security.oauth2.server.resource.BearerTokenErrors.invalidToken;

/**
 * The {@link BearerTokenResolver} implementation based on RFC 6750.
 * В отличие от {@link org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver}
 * дополнительно извлекает токен {@link Jwt} ещё и из http-сесии.
 * После извлечения, токен ДОЛЖЕН быть валидирован на предмет истечения срока действия.
 *
 * @since Spring Security 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750 Section 2: Authenticated Requests</a>
 */
public class SessionAwareBearerTokenResolver implements BearerTokenResolver {

    private static final Pattern authorizationPattern = Pattern.compile(
            "^Bearer (?<token>[a-zA-Z0-9-._~+/]+)=*$",
            Pattern.CASE_INSENSITIVE);

    private boolean allowFormEncodedBodyParameter = false;

    private boolean allowUriQueryParameter = false;

    /**
     * {@inheritDoc}
     */
    @Override
    public String resolve(HttpServletRequest request) {

        String authorizationHeaderToken = resolveFromAuthorizationHeader(request);
        String parameterToken = resolveFromRequestParameters(request);
        String tokenValue = null;

        if (authorizationHeaderToken != null) {
            if (parameterToken != null) {
                BearerTokenError error = invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            }
            tokenValue = authorizationHeaderToken;

        } else if (parameterToken != null && isParameterTokenSupportedForRequest(request)) {

            tokenValue = parameterToken;

        } else {

            Authentication storedAuthentication = SecurityContextHolder.getContext().getAuthentication();
            if (storedAuthentication instanceof AbstractOAuth2TokenAuthenticationToken) {

                AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token> tokenAuthentication =
                        (AbstractOAuth2TokenAuthenticationToken<? extends AbstractOAuth2Token>) storedAuthentication;

                AbstractOAuth2Token token = tokenAuthentication.getToken();
                if (token != null) {
                    tokenValue = token.getTokenValue();
                }
            }
        }
        return tokenValue;
    }

    /**
     * Set if transport of access token using form-encoded body parameter is supported. Defaults to {@code false}.
     * @param allowFormEncodedBodyParameter if the form-encoded body parameter is supported
     */
    public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
        this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
    }

    /**
     * Set if transport of access token using URI query parameter is supported. Defaults to {@code false}.
     *
     * The spec recommends against using this mechanism for sending bearer tokens, and even goes as far as
     * stating that it was only included for completeness.
     *
     * @param allowUriQueryParameter if the URI query parameter is supported
     */
    public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter = allowUriQueryParameter;
    }

    private static String resolveFromAuthorizationHeader(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
            Matcher matcher = authorizationPattern.matcher(authorization);

            if (!matcher.matches()) {
                BearerTokenError error = invalidToken("Bearer token is malformed");
                throw new OAuth2AuthenticationException(error);
            }

            return matcher.group("token");
        }
        return null;
    }

    private static String resolveFromRequestParameters(HttpServletRequest request) {
        String[] values = request.getParameterValues("access_token");
        if (values == null || values.length == 0)  {
            return null;
        }

        if (values.length == 1) {
            return values[0];
        }

        BearerTokenError error = invalidRequest("Found multiple bearer tokens in the request");
        throw new OAuth2AuthenticationException(error);
    }

    private boolean isParameterTokenSupportedForRequest(HttpServletRequest request) {
        return ((this.allowFormEncodedBodyParameter && "POST".equals(request.getMethod()))
                || (this.allowUriQueryParameter && "GET".equals(request.getMethod())));
    }
}
