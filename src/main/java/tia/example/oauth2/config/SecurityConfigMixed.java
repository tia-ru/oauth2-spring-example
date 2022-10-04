package tia.example.oauth2.config;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import tia.example.oauth2.security.AuthNProviders;
import tia.example.oauth2.security.CmjJwtAuthenticationConverter;
import tia.example.oauth2.security.CmjOpaqueTokenAuthenticationProvider;
import tia.example.oauth2.security.IntrospectionAuthenticationMethod;
import tia.example.oauth2.security.SessionAwareBearerTokenResolver;
import tia.example.oauth2.security.UserAccessTokenAuthenticationEntityConverter;
import tia.example.oauth2.security.UserInfoOpaqueTokenIntrospector;

@EnableWebSecurity(debug = true)
public class SecurityConfigMixed extends WebSecurityConfigurerAdapter {

    // jwt,opaque,basic,header
    @Value("${authNProviders:jwt, basic}")
    private Set<AuthNProviders> enabledAuthNProviders;

    // true требует работающего IDP при старте CMJ
    @Value("${useOidcProviderMeta:false}")
    boolean useOidcProviderMeta;

    //===== JWT-token mode parameters ==========================================
    // http://localhost:8080/auth/realms/Demo/protocol/openid-connect/certs
    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}")
    String jwkSetUri;

    // Значение обязательно для jwt-режима для проверки совпадения с клаймом iss в токене
    // или при useOidcProviderMeta==true
    // http://localhost:8080/auth/realms/Demo
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    String issuerUri;

    //===== Opaque token mode parameters ==========================================

    //http://localhost:8080/auth/realms/Demo/protocol/openid-connect/token/introspect
    @Value("${spring.security.oauth2.resourceserver.opaque-token.introspection-uri:}")
    String introspectionUri;
    @Value("${spring.security.oauth2.resourceserver.opaque-token.client-id:}")
    String clientId;
    @Value("${spring.security.oauth2.resourceserver.opaque-token.client-secret:}")
    String clientSecret;

    @Value("${spring.security.oauth2.resourceserver.opaque-token.use-user-info:false}")
    boolean useUserInfoEndpoint;

    @Value("${spring.security.oauth2.resourceserver.opaque-token.introspection.authentication.method:basic}")
    IntrospectionAuthenticationMethod introspectionAuthenticationMethod;
    private OIDCProviderMetadata oidcMetadata = null;

   /* public SecurityConfigJwt(){
        super(true);
    }*/

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        /*BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        User.UserBuilder user = User.builder().passwordEncoder(s -> passwordEncoder.encode(s));

        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder)
                .withUser(user.username("user").password("password"))
                .withUser(user.username("z1").password("1"))
                ;*/
        auth.inMemoryAuthentication()
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                .withUser("user").password("password").roles("USER").and()
                .withUser("z1").password("1").roles("USER").and()
                .withUser("user11").password("").roles("USER").and()
                .withUser("user11 test").password("").roles("USER").and()
                .withUser("user12").password("").roles("USER").and()
                .withUser("user13").password("").roles("USER").and()
                .withUser("user14").password("").roles("USER").and()
                .withUser("user21").password("").roles("USER").and()
                .withUser("user21 test").password("").roles("USER").and()
                .withUser("user22").password("").roles("USER").and()
                .withUser("user22 test").password("").roles("USER").and()
                .withUser("user23").password("").roles("USER").and()
                .withUser("user24").password("").roles("USER").and()
                .withUser("hnelson").password("").roles("USER").and()
                .withUser("admin").password("password").roles("USER", "ADMIN");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authorize -> authorize
                    //.mvcMatchers("/api/**").hasAuthority("SCOPE_message:read")
                    .anyRequest()
                    .authenticated()
            )
            .sessionManagement();

        if (enabledAuthNProviders.contains(AuthNProviders.jwt)) {
            // JWT token
            http.oauth2ResourceServer(oauth2 -> oauth2
                    .bearerTokenResolver(new SessionAwareBearerTokenResolver())
                    .jwt(jwt -> jwt
                        // Позволяет стартовать приложение без предварительного запуска сервера аутентификации
                        //.jwkSetUri(getJWKSetURI())
                        .jwtAuthenticationConverter(new CmjJwtAuthenticationConverter(userDetailsService()))
                        .decoder(getJwtDecoder())
                    )
            );

        } else if (enabledAuthNProviders.contains(AuthNProviders.opaque)) {
            // Opaque token

            http
                //.authenticationProvider(new CmjOpaqueTokenAuthenticationProvider(introspector))
                .oauth2ResourceServer(oauth2 -> oauth2
                    //.bearerTokenResolver(new SessionAwareBearerTokenResolver())
                    .opaqueToken(o -> o
                        .authenticationManager(new ProviderManager(
                                new CmjOpaqueTokenAuthenticationProvider(introspector())))
                    )
                );
        }
        if (enabledAuthNProviders.contains(AuthNProviders.header)) {
            http.authenticationProvider(chAuthenticationProvider()).addFilter(chRequestHeaderAuthenticationFilter());
        }
        if (enabledAuthNProviders.contains(AuthNProviders.basic)) {
            http.httpBasic(b -> b.authenticationEntryPoint(getBasicEntryPoint()));
        }

    }
    @Bean
    OpaqueTokenIntrospector introspector() {
        OpaqueTokenIntrospector introspector;
        if (introspectionAuthenticationMethod == IntrospectionAuthenticationMethod.user_access_token) {
            //FAM
            NimbusOpaqueTokenIntrospector nimbusIntrospector = new NimbusOpaqueTokenIntrospector(getIntrospectionUri(), new RestTemplate());
            nimbusIntrospector.setRequestEntityConverter(new UserAccessTokenAuthenticationEntityConverter(getIntrospectionUri()));
            introspector = nimbusIntrospector;
        } else {
            introspector = new NimbusOpaqueTokenIntrospector(getIntrospectionUri(), clientId, clientSecret);
        }

        if (useUserInfoEndpoint) {
            ClientRegistration clientRegistration = clientRegistration();
            introspector = new UserInfoOpaqueTokenIntrospector(introspector, clientRegistration);
        }
        return introspector;
    }

    ClientRegistration clientRegistration() {
        ClientRegistration clientRegistration = null;
        if (useOidcProviderMeta && !issuerUri.isEmpty()) {
            clientRegistration = ClientRegistrations.fromIssuerLocation(issuerUri)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    //.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .userNameAttributeName("name")
                    //.userNameAttributeName("preferred_username")
                    .build();
        }
        if (clientRegistration == null) {
            // TODO Сделать свойства для всех значений ниже
            clientRegistration = ClientRegistration.withRegistrationId("idp")
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                    .jwkSetUri(jwkSetUri)
                    .userInfoUri("")
                    .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
                    .userNameAttributeName("username")
                    .tokenUri("")
                    .build();
        }
        return clientRegistration;
    }

    private CmBasicAuthenticationEntryPoint getBasicEntryPoint() {
        CmBasicAuthenticationEntryPoint entryPoint = new CmBasicAuthenticationEntryPoint();
        entryPoint.setRealmName("CompanyMedia");
        return entryPoint;
    }

    RequestHeaderAuthenticationFilter chRequestHeaderAuthenticationFilter() {
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setPrincipalRequestHeader("X-Custom");
        filter.setExceptionIfHeaderMissing(false);
        filter.setContinueFilterChainOnUnsuccessfulAuthentication(true);
        filter.setAuthenticationManager(new RequestHeaderAuthenticationManager());
        return filter;
    }

    PreAuthenticatedAuthenticationProvider chAuthenticationProvider() {
        UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>();
        wrapper.setUserDetailsService(super.userDetailsService());

        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(wrapper);

        return provider;
    }

    private JwtDecoder getJwtDecoder() {
        //В отличие от JwtDecoders.fromOidcIssuerLocation() данная конфигурация не требует работающего IDP на момент старта CMJ
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(getJWKSetURI()).build();
        OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(issuerUri);
        jwtDecoder.setJwtValidator(jwtValidator);
        return jwtDecoder;
    }

    private Optional<OIDCProviderMetadata> getOidcMeta() {
        if (oidcMetadata == null && useOidcProviderMeta && !issuerUri.isEmpty()) {
            try {
                final Issuer iss = Issuer.parse(issuerUri);
                oidcMetadata = OIDCProviderMetadata.resolve(iss);

            } catch (GeneralException | IOException ignore) {
            }
        }
        return Optional.ofNullable(oidcMetadata);
    }

    private String getJWKSetURI() {
        if (jwkSetUri.isEmpty()) {
            jwkSetUri = getOidcMeta().map(m -> m.getJWKSetURI().toASCIIString()).orElse("");
        }
        return jwkSetUri;
    }

    private String getIntrospectionUri(){
        if (introspectionUri.isEmpty()) {
            introspectionUri = getOidcMeta().map(m -> m.getIntrospectionEndpointURI().toASCIIString()).orElse("");
            //TODO
            /*introspectionUri = getClientRegistration().map(
                    m -> (String) m.getProviderDetails().getConfigurationMetadata().get("introspection_endpoint")
            ).orElse("");*/
        }
        return introspectionUri;
    }
}