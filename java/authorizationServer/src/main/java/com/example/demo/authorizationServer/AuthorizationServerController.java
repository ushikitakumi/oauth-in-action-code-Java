package com.example.demo.authorizationServer;

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
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Controller
public class AuthorizationServerController {

    private String accessToken = null;
    private String scope = null;
    private String state = null;
    private final int STATE_LENGTH = 10;

    private final Map<String, String > authServerEndpoints = Map.of(
            "authorizationEndpoint", "http://localhost:9001/authorize",
            "tokenEndpoint", "http://localhost:9001/token"
    );

    private final Map<String, String > clientConriguration = Map.of(
            "clientId", "oauth-client-1",
            "clientSecret", "oauth-client-secret-1",
            "redirectUri", "http://localhost:9000/callback",
            "scope", "foo bar"
    );

    private final Map<String, Map<String, String>> requests = new ConcurrentHashMap<>();

    @GetMapping(path = "/")
    public String index(Model model) {
        model.addAttribute("clients", clientConriguration);
        model.addAttribute("authServer", authServerEndpoints);
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize(@RequestParam Map<String, String> params, Model model) {
        String clientId = params.get("client_id");
        String redirectUri = params.get("redirect_uri");
        String reqScope = params.get("scope");

        // 単純なクライアント取得 (このプロジェクトでは1クライアントの固定設定を使用)
        if (clientId == null || !clientId.equals(clientConriguration.get("clientId"))) {
            model.addAttribute("error", "Unknown client");
            return "error";
        }

        // redirect_uri の検証
        String allowedRedirect = clientConriguration.get("redirectUri");
        if (redirectUri == null || !redirectUri.equals(allowedRedirect)) {
            model.addAttribute("error", "Invalid redirect URI");
            return "error";
        }

        // スコープ検証: 要求スコープがクライアント許可スコープのサブセットかチェック
        List<String> requestedScopes = reqScope != null && !reqScope.isEmpty()
                ? Arrays.stream(reqScope.split(" ")).collect(Collectors.toList())
                : List.of();
        List<String> clientScopes = clientConriguration.get("scope") != null
                ? Arrays.stream(clientConriguration.get("scope").split(" ")).toList()
                : List.of();

        if (!requestedScopes.isEmpty()) {
            boolean invalid = requestedScopes.stream().anyMatch(s -> !clientScopes.contains(s));
            if (invalid) {
                // invalid_scope を redirect_uri に付与してリダイレクト
                String redirectWithError = UriComponentsBuilder.fromUriString(redirectUri)
                        .queryParam("error", "invalid_scope")
                        .build()
                        .toUriString();
                return "redirect:" + redirectWithError;
            }
        }

        // リクエストID を生成して保存（承認ページから参照するため）
        String reqid = new RandomStringGenerator.Builder().withinRange('a', 'z').build().generate(8);
        requests.put(reqid, params);

        // approve テンプレートに表示する属性をセット
        model.addAttribute("client", clientConriguration);
        model.addAttribute("reqid", reqid);
        model.addAttribute("scope", requestedScopes);

        return "approve";
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
