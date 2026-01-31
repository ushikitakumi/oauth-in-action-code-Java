package com.example.demo.authorizationServer;

import org.apache.commons.text.RandomStringGenerator;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Controller
public class AuthorizationServerController {

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

    // 追加: 認可コードとリフレッシュトークンの簡易的な保存領域
    private final Map<String, Map<String, String>> authorizationCodes = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> refreshTokens = new ConcurrentHashMap<>();

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
        String reqid = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(8);
        requests.put(reqid, params);

        // approve テンプレートに表示する属性をセット
        model.addAttribute("client", clientConriguration);
        model.addAttribute("reqid", reqid);
        model.addAttribute("scope", requestedScopes);

        return "approve";
    }

    @PostMapping(path = "/approve")
    public String approve(@RequestParam String reqid,
                          @RequestParam String approve,
                          Model model) {
        Map<String, String> reqParams = requests.get(reqid);
        requests.remove(reqid);
        if (reqParams == null) {
            model.addAttribute("error", "No matching authorization request");
            return "error";
        }

        String redirectUri = reqParams.get("redirect_uri");
        if (approve != null) {
            if (reqParams.get("reponse_type") == null || !reqParams.get("response_type").equals("code")) {
                // unsupported_response_type を redirect_uri に付与してリダイレクト
                String redirectWithError = UriComponentsBuilder.fromUriString(redirectUri)
                        .queryParam("error", "unsupported_response_type")
                        .queryParam("state", reqParams.get("state"))
                        .build()
                        .toUriString();
                return "redirect:" + redirectWithError;
            }
            // 承認された場合、認可コードを生成して redirect_uri にリダイレクト
            String authorizationCode = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(12);

            // 生成した認可コードを保存（/token で交換可能にするため）
            authorizationCodes.put(authorizationCode, reqParams);

            String redirectWithCode = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("code", authorizationCode)
                    .queryParam("state", reqParams.get("state"))
                    .build()
                    .toUriString();
            return "redirect:" + redirectWithCode;
        } else {
            // 拒否された場合、error を redirect_uri に付与してリダイレクト
            String redirectWithError = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("error", "access_denied")
                    .queryParam("state", reqParams.get("state"))
                    .build()
                    .toUriString();
            return "redirect:" + redirectWithError;
        }
    }

    // POST /token エンドポイントを追加
    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam MultiValueMap<String, String> formParams,
                                                     @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        // クライアント認証 (HTTP Basic があれば優先)
        String clientId = null;
        String clientSecret = null;
        if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("basic ")) {
            try {
                String base64 = authorizationHeader.substring(6).trim();
                String decoded = new String(java.util.Base64.getDecoder().decode(base64));
                int idx = decoded.indexOf(':');
                if (idx > 0) {
                    clientId = decoded.substring(0, idx);
                    clientSecret = decoded.substring(idx + 1);
                }
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_client", "error_description", "Invalid authorization header"));
            }
        }
        if (clientId == null) {
            clientId = formParams.getFirst("client_id");
            clientSecret = formParams.getFirst("client_secret");
        }

        if (clientId == null || clientSecret == null || !clientId.equals(clientConriguration.get("clientId")) || !clientSecret.equals(clientConriguration.get("clientSecret"))) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_client"));
        }

        String grantType = formParams.getFirst("grant_type");
        if (grantType == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "error_description", "grant_type is required"));
        }

        // authorization_code グラント
        if (grantType.equals("authorization_code")) {
            String code = formParams.getFirst("code");
            if (code == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "error_description", "code is required"));
            }
            Map<String, String> saved = authorizationCodes.remove(code);
            if (saved == null) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "authorization code is invalid or has been used"));
            }
            // client_id と redirect_uri の照合
            String codeClientId = saved.get("client_id");
            String codeRedirect = saved.get("redirect_uri");
            if (!clientId.equals(codeClientId)) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "client_id does not match authorization code"));
            }
            String redirectUri = formParams.getFirst("redirect_uri");
            if (redirectUri != null && !redirectUri.equals(codeRedirect)) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "redirect_uri mismatch"));
            }

            // トークンを作成
            String accessToken = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(24);
            String refreshToken = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(24);

            // リフレッシュトークンを保存
            refreshTokens.put(refreshToken, Map.of("client_id", clientId, "scope", saved.getOrDefault("scope", "")));

            Map<String, Object> resp = Map.of(
                    "access_token", accessToken,
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "refresh_token", refreshToken
            );
            return ResponseEntity.ok(resp);
        }

        // refresh_token グラント
        if (grantType.equals("refresh_token")) {
            String rtoken = formParams.getFirst("refresh_token");
            if (rtoken == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "error_description", "refresh_token is required"));
            }
            Map<String, String> saved = refreshTokens.get(rtoken);
            if (saved == null) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "refresh token invalid"));
            }
            if (!clientId.equals(saved.get("client_id"))) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "client_id does not match refresh token"));
            }

            // 新しいアクセストークンを発行（リフレッシュトークンはローテーションしてもよいが簡単のため再発行）
            String newAccess = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(24);
            String newRefresh = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(24);
            // 旧リフレッシュトークンを削除して新しいものを保存
            refreshTokens.remove(rtoken);
            refreshTokens.put(newRefresh, Map.of("client_id", clientId, "scope", saved.getOrDefault("scope", "")));

            Map<String, Object> resp = Map.of(
                    "access_token", newAccess,
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "refresh_token", newRefresh
            );
            return ResponseEntity.ok(resp);
        }

        // client_credentials グラント
        if (grantType.equals("client_credentials")) {
            String newAccess = new RandomStringGenerator.Builder().withinRange('a', 'z').get().generate(24);
            Map<String, Object> resp = Map.of(
                    "access_token", newAccess,
                    "token_type", "Bearer",
                    "expires_in", 3600
            );
            return ResponseEntity.ok(resp);
        }

        // 未対応の grant_type
        return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
    }
}
