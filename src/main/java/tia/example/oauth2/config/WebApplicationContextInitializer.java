package tia.example.oauth2.config;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;

public class WebApplicationContextInitializer implements ApplicationContextInitializer {

    private final static String PROFILE_WORK_PROP = "cmj.auth.profile";

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        String profile = environment.getProperty(PROFILE_WORK_PROP, CmjSpringProfiles.AUTHN_OIDC);
        if (profile.isEmpty()) profile = CmjSpringProfiles.AUTHN_OIDC;
        environment.addActiveProfile(profile);
    }
}
