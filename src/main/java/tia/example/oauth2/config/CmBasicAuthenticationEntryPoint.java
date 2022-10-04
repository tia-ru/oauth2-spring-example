package tia.example.oauth2.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

public class CmBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

    private static final String WEBDOCS_CLIENT_ALIAS = "Webdocs";
    private static final String STD_CM_CLIENT_ALIAS = "CM-Web";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
            throws IOException{

        handleWwwAuthenticateHeader(request, response);
        
		//RestResponseHelper.handleResponse(response, ex.getMessage());
        //response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    private void handleWwwAuthenticateHeader(HttpServletRequest request, HttpServletResponse response) {

        final String clientHeader = request.getHeader("Client");
        if (clientHeader != null && (clientHeader.startsWith(WEBDOCS_CLIENT_ALIAS) || clientHeader.startsWith(STD_CM_CLIENT_ALIAS))) {
            response.setHeader("WWW-Authenticate", null);
        } else {
            response.addHeader("WWW-Authenticate", "Basic realm=\"" + getRealmName() + "\"");
        }
    }

}
