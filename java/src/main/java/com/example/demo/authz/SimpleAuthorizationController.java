package com.example.demo.authz;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;

@Controller
public class SimpleAuthorizationController {

    // map code -> username
    private final Map<String, String> codes = new ConcurrentHashMap<>();

    @GetMapping("/authorize")
    public RedirectView authorize(@RequestParam String response_type,
                                  @RequestParam String client_id,
                                  @RequestParam String redirect_uri,
                                  @RequestParam(required = false) String state) {
        // In a real AS, you'd show a consent/login screen. Here we auto-approve for the demo.
        String code = UUID.randomUUID().toString();
        // issue code for a demo user
        codes.put(code, "user");
        String redirect = redirect_uri + "?code=" + code + (state != null ? "&state=" + state : "");
        return new RedirectView(redirect);
    }

    public String consumeCode(String code) {
        return codes.remove(code);
    }
}

