package tia.example.oauth2.security;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Метод аутентификации CMJ в IDP для интроспекции access-токена.
 */
public enum IntrospectionAuthorizationGrantType {
    ;
    /** Аналог Basic, где логин=<ClientId>, а пароль=<secret>. Secret выдаётся при регистрации в IDP.*/
    public static final AuthorizationGrantType CLIENT_CREDENTIALS = AuthorizationGrantType.CLIENT_CREDENTIALS;

    /** В заголовке "Authorization: Bearer... "передаётся access-токен пользователя. Не стандартный механизм, но встретился в AvanPost FAM */
    public static final AuthorizationGrantType USER_ACCESS_TOKEN = new AuthorizationGrantType("user_access_token");
}
