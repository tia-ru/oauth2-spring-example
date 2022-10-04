package tia.example.oauth2.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import tia.example.oauth2.security.CmUserDetailsLTPA;

@Controller
public class ProtectedController {

    @GetMapping("/resource")
    @ResponseBody
    public String getResource(@AuthenticationPrincipal CmUserDetailsLTPA principal){
        String name = principal.getName();
        String subject = principal.getSubject();
        String preferred_username = principal.getClaimAsString("preferred_username");
        return "{\n" +
                "  \"Name\": \"" + name +"\",\n" +
                "  \"Subject\": \"" + subject +"\",\n" +
                "  \"preferred_username\": \"" + preferred_username +"\",\n" +
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
        String name = principal.getName();
        String user = principal.getAttribute("preferred_username");
        return "{\n" +
                "  \"Name\": \"" + name +"\",\n" +
                "  \"preferred_username\": \"" + user +"\",\n" +
                "  \"Age\": 20\n" +
                "}";
    }*/

}
