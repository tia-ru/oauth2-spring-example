package tia.example.oauth2.config;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;

public class WebApplicationContextInitializer implements ApplicationContextInitializer {
    public final static String PROFILE_WORK_PROP = "cmj.auth.profile";
    private final static String PROFILE_DEFAULT_PROP_VALUE = "basic";

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        String profile = environment.getProperty(PROFILE_WORK_PROP, PROFILE_DEFAULT_PROP_VALUE);
        if (profile.isEmpty()) profile = PROFILE_DEFAULT_PROP_VALUE;
        environment.addActiveProfile(profile);
    }
}
