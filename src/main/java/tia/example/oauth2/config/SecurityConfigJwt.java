package tia.example.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import tia.example.oauth2.security.CmjJwtAuthenticationConverter;
import tia.example.oauth2.security.SessionAwareBearerTokenResolver;

@EnableWebSecurity(debug = true)
@Profile(CmjSpringProfiles.AUTHN_OIDC)
public class SecurityConfigJwt extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    String jwkSetUri;


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("password").roles("USER")
                .and()
                .withUser("z1").password("1").roles("USER")
                .and()
                .withUser("admin").password("password").roles("USER", "ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests(authorize -> authorize
            //.mvcMatchers("/api/**").hasAuthority("SCOPE_message:read")
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .bearerTokenResolver(new SessionAwareBearerTokenResolver())
            .jwt()
                .jwkSetUri(jwkSetUri)// Позволяет стартовать приложение без предварительного запуска сервера аутентификации
                .jwtAuthenticationConverter(new CmjJwtAuthenticationConverter(userDetailsService()))
        )
        ;
    }
}