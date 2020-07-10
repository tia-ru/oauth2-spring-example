package tia.example.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import tia.example.oauth2.security.CmUserDetailsLTPA;

@Controller
public class ProtectedController {

    @GetMapping("/resource")
    @ResponseBody
    public String getResource(@AuthenticationPrincipal CmUserDetailsLTPA principal){
        String user = principal.getName();
        return "{\n" +
                "  \"Name\": \"" + user +"\",\n" +
                "  \"Age\": 20\n" +
                "}";
    }

    // For JWT
    /*@GetMapping("/resource")
    @ResponseBody
    public String getResource(@AuthenticationPrincipal Jwt jwt){
        String user = jwt.getClaimAsString("preferred_username");
        return "{\n" +
                "  \"Name\": \"" + user +"\",\n" +
                "  \"Age\": 20\n" +
                "}";
    }*/

    // For opaqueToken
   /* @GetMapping("/resource")
    @ResponseBody
    public String getResource(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal){
        String user = principal.getAttribute("preferred_username");
        return "{\n" +
                "  \"Name\": \"" + user +"\",\n" +
                "  \"Age\": 20\n" +
                "}";
    }*/
}
