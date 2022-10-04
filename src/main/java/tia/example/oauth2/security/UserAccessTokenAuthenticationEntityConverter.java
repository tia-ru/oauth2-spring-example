package tia.example.oauth2.security;

import java.net.URI;
import java.util.Collections;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * В отличии от дефолтного конвертера, используемого в NimbusOpaqueTokenIntrospector, этот
 * добавляет access-токен пользователя в заголовок <br/>
 * {@code Authorization: Bearer <token>}<br/>
 * , а в тело поле <br/>
 * {@code token_type_hint=access_token}
 */
public class UserAccessTokenAuthenticationEntityConverter implements Converter<String, RequestEntity<?>> {

    private final URI introspectionUri;

    public UserAccessTokenAuthenticationEntityConverter(String introspectionUri) {
        this.introspectionUri = URI.create(introspectionUri);
    }

    @Override
    public RequestEntity<?> convert(String token) {
        HttpHeaders headers = requestHeaders(token);
        MultiValueMap<String, String> body = requestBody(token);
        return new RequestEntity<>(body, headers, HttpMethod.POST, introspectionUri);
    }

    private HttpHeaders requestHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        //headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    private MultiValueMap<String, String> requestBody(String token) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.set("token", token);
        body.add("token_type_hint", "access_token"); //Valid values: access_token, id_token, refresh_token, and device_secret
        return body;
    }
}
