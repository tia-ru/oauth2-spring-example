package tia.example.oauth2.config;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.FrameworkServlet;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import javax.servlet.Filter;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.SessionCookieConfig;

public class WebApplicationInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {


    @Override
    protected String[] getServletMappings() {
        return new String[]{"/api/*"};
    }

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return null;// TODO Определить контекст CMJ
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class[]{WebMvcConfig.class};
    }

    @Override
    protected FrameworkServlet createDispatcherServlet(WebApplicationContext servletAppContext) {
        FrameworkServlet dispatcherServlet = super.createDispatcherServlet(servletAppContext);
        return dispatcherServlet;
    }

    @Override
    protected Filter[] getServletFilters() {
       return new Filter[]{new DelegatingFilterProxy("springSecurityFilterChain")};
    }

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        super.onStartup(servletContext);
        servletContext.addListener(new HttpSessionEventPublisher());

        servletContext.setSessionTimeout(10);
        SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
        sessionCookieConfig.setName("CMJSID"); //Куку с именем JSessionId Wildfly автоматически делает Secured (или браузер?)
        sessionCookieConfig.setHttpOnly(true);
        sessionCookieConfig.setMaxAge(10*60);
        // Secured кука не устанавливается в браузере без TLS-соединения.
        // TODO Включить в продуктиве.
        //sessionCookieConfig.setSecure(true);
    }

    @Override
    protected ApplicationContextInitializer<?>[] getServletApplicationContextInitializers() {
        return new ApplicationContextInitializer[]{new WebApplicationContextInitializer()};
    }
}