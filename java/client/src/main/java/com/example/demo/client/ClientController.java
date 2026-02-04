package com.example.demo.client;

import org.apache.commons.text.RandomStringGenerator;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;

@Controller
public class ClientController {

    private String accessToken = null;
    private final String scope = null;
    private String state = null;

    private final Map<String, String > authServerEndpoints = Map.of(
            "authorizationEndpoint", "http://localhost:9001/authorize",
            "tokenEndpoint", "http://localhost:9001/token"
    );

    private final Map<String, String > clientConriguration = Map.of(
            "clientId", "oauth-client-1",
            "clientSecret", "oauth-client-secret-1",
            "redirectUri", "http://localhost:9000/callback"
    );

    @GetMapping(path = "/")
    public String index(Model model) {
        model.addAttribute("access_token", accessToken);
        model.addAttribute("scope", scope);
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize(RedirectAttributes redirectAttributes) {
        accessToken = null;
        int STATE_LENGTH = 10;
        state = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(STATE_LENGTH);

        redirectAttributes.addAttribute("response_type", "code");
        redirectAttributes.addAttribute("client_id", clientConriguration.get("clientId"));
        redirectAttributes.addAttribute("redirect_uri", clientConriguration.get("redirectUri"));
        redirectAttributes.addAttribute("state", state);

        return "redirect:" + authServerEndpoints.get("authorizationEndpoint");
    }

    @GetMapping(path = "/callback")
    public String callback(@RequestParam(required = false) String error,
                           @RequestParam(required = false) String code,
                           @RequestParam String state,
                           Model model) {

        if (error != null) {
            model.addAttribute("error", error);
            return "error";
        }

        if (state == null || !state.equals(this.state)) {
            model.addAttribute("error", "State value did not match");
            return "error";
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("code", code);
        formData.add("redirect_uri", clientConriguration.get("redirectUri"));

        ResponseEntity<Map> response = RestClient.create().post()
                .uri(authServerEndpoints.get("tokenEndpoint"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(h -> h.setBasicAuth(clientConriguration.get("clientId"), clientConriguration.get("clientSecret")))
                .body(formData)
                .retrieve()
                .toEntity(Map.class);

        int statusCodeValue = response.getStatusCode().value();

        if (statusCodeValue >= 200 && statusCodeValue < 300) {
            model.addAttribute("access_token", response.getBody().get("access_token"));
            model.addAttribute("scope", scope);
            return "data";
        } else {
            model.addAttribute("error", "Unable to fetch access token, server response: " + statusCodeValue);
            return "error";
        }
    }
}
