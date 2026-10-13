package com.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.google.gson.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/** Synthetic mocks only: never starts NanoHTTPD or a Burp application. */
public final class SafetyRegressionTest {
    private static int checks;
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
    private static JsonObject json(String text) { return JsonParser.parseString(text).getAsJsonObject(); }
    private static void denied(Runnable action) {
        boolean denied = false;
        try { action.run(); } catch (IllegalArgumentException ex) { denied = true; }
        check(denied, "Expected policy denial");
    }
    @SuppressWarnings("unchecked")
    private static <T> T mock(Class<T> type, Function<Method, Object> call) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
            (proxy, method, args) -> call.apply(method));
    }
    private static ProxyHttpRequestResponse entry(String url) {
        HttpRequest request = mock(HttpRequest.class, method -> switch (method.getName()) {
            case "url" -> url;
            case "method" -> "GET";
            case "toString" -> "synthetic request " + url;
            default -> throw new AssertionError("Unexpected request method: " + method);
        });
        return mock(ProxyHttpRequestResponse.class, method -> switch (method.getName()) {
            case "finalRequest" -> request;
            case "response" -> null;
            default -> throw new AssertionError("Unexpected entry method: " + method);
        });
    }
    private static void isolationChecks() throws Exception {
        if (!Boolean.getBoolean("test.requireIsolation")) return;
        check(System.getSecurityManager() != null, "Test SecurityManager must be active");
        try { new Socket("127.0.0.1", 9); throw new AssertionError("Network allowed"); }
        catch (SecurityException expected) { checks++; }
        try { Files.readString(Path.of("/etc/hostname")); throw new AssertionError("Host read allowed"); }
        catch (SecurityException expected) { checks++; }
        try { Files.writeString(Path.of("/tmp/reverse-skill-denied"), "synthetic"); throw new AssertionError("Host write allowed"); }
        catch (SecurityException expected) { checks++; }
        try { new ProcessBuilder("true").start(); throw new AssertionError("Process allowed"); }
        catch (SecurityException expected) { checks++; }
    }
    public static void main(String[] args) throws Exception {
        isolationChecks();
        SafetyPolicy safe = new SafetyPolicy(false);
        denied(() -> safe.scope(false));
        denied(() -> safe.privacy(false));
        check(safe.scopeEnabled() && safe.privacyStrict(), "Default protections changed");
        for (String tool : List.of("send_request", "cookie_jar", "proxy_detail", "passive_intel",
                "export_config", "scan", "crawl", "send_request_parallel", "websocket_create", "unknown_future_tool")) {
            denied(() -> safe.check(tool, new JsonObject(), url -> { throw new AssertionError("Unnecessary scope lookup"); }));
        }
        SafetyPolicy scoped = new SafetyPolicy(true);
        scoped.privacy(false);
        AtomicInteger scopeChecks = new AtomicInteger();
        scoped.check("send_request", json("{\"url\":\"https://allowed.invalid/path\"}"), url -> {
            scopeChecks.incrementAndGet(); return url.equals("https://allowed.invalid/path");
        });
        check(scopeChecks.get() == 1, "URL scope was not checked");
        denied(() -> scoped.check("send_request", json("{\"url\":\"https://outside.invalid/\"}"), url -> false));
        for (String url : List.of("file:///tmp/a", "https://user:pass@allowed.invalid/", "https://allowed.invalid/#fragment", "garbage")) {
            JsonObject p = new JsonObject(); p.addProperty("url", url);
            denied(() -> scoped.check("send_request", p, value -> true));
        }
        for (String unsafe : List.of(
                "{\"url\":\"https://allowed.invalid/\",\"method\":\"GET\\r\\nHost: outside.invalid\"}",
                "{\"url\":\"https://allowed.invalid/\",\"headers\":{\"Host\":\"outside.invalid\"}}",
                "{\"url\":\"https://allowed.invalid/\",\"headers\":{\"X-Test\":\"a\\r\\nb\"}}")) {
            denied(() -> scoped.check("send_request", json(unsafe), url -> true));
        }
        denied(() -> scoped.check("send_request_parallel", new JsonObject(), url -> true));
        for (String p : List.of("{\"limit\":-1}", "{\"limit\":1.5}", "{\"threads\":21}",
                "{\"count\":101}", "{\"from\":0,\"to\":1000}", "{\"offset\":\"1\"}")) {
            denied(() -> safe.check("encode", json(p), url -> true));
        }
        JsonArray many = new JsonArray(); for (int i = 0; i < 101; i++) many.add("synthetic");
        JsonObject p = new JsonObject(); p.add("wordlist", many);
        denied(() -> safe.check("encode", p, url -> true));
        AtomicInteger apiCalls = new AtomicInteger();
        MontoyaApi untouched = mock(MontoyaApi.class, method -> {
            apiCalls.incrementAndGet(); throw new AssertionError("Denied operation reached Montoya");
        });
        McpHttpServer locked = new McpHttpServer(untouched, 0, "synthetic-test-token", false);
        for (String tool : List.of("send_request", "cookie_jar", "proxy_detail", "passive_intel", "import_config", "scan")) {
            JsonObject result = locked.dispatch(tool, json("{\"url\":\"https://outside.invalid/\"}"));
            check(result.has("error") && "POLICY_DENIED".equals(result.get("code").getAsString()), "Dispatch failed open");
            check(!result.toString().contains("synthetic-secret"), "Secret escaped");
        }
        check(locked.dispatch("privacy_mode", json("{\"mode\":\"off\"}")).has("error"), "Remote privacy downgrade");
        check(locked.dispatch("scope_gate", json("{\"action\":\"disable\"}")).has("error"), "Remote scope downgrade");
        check(apiCalls.get() == 0, "Denied calls touched Montoya");
        // Scope-only policy also rejects unreviewed operations at the actual dispatch boundary.
        McpHttpServer scopeOnly = new McpHttpServer(untouched, 0, "synthetic-test-token", true);
        scopeOnly.dispatch("privacy_mode", json("{\"mode\":\"off\"}"));
        check(scopeOnly.dispatch("send_request_parallel", new JsonObject()).has("error"), "Bulk escaped scope gate");
        check(scopeOnly.dispatch("cookie_jar", new JsonObject()).has("error"), "Session read escaped scope gate");
        check(apiCalls.get() == 0, "Scope denial touched Montoya");

        AtomicInteger scopeLookups = new AtomicInteger();
        burp.api.montoya.scope.Scope scope = mock(burp.api.montoya.scope.Scope.class, method -> {
            scopeLookups.incrementAndGet(); return false;
        });
        MontoyaApi scopedApi = mock(MontoyaApi.class, method -> {
            if (method.getName().equals("scope")) return scope;
            throw new AssertionError("Out-of-scope request reached transport");
        });
        McpHttpServer scopedServer = new McpHttpServer(scopedApi, 0, "synthetic-test-token", true);
        scopedServer.dispatch("privacy_mode", json("{\"mode\":\"off\"}"));
        check(scopedServer.dispatch("send_request", json("{\"url\":\"https://outside.invalid/\"}")).has("error"), "Out-of-scope dispatch allowed");
        check(scopeLookups.get() == 1, "Dispatch did not consult scope");
        scopedServer.stop();

        List<ProxyHttpRequestResponse> history = new ArrayList<>(List.of(entry("https://a.invalid/"), entry("https://b.invalid/")));
        burp.api.montoya.proxy.Proxy proxy = mock(burp.api.montoya.proxy.Proxy.class, method -> {
            if (method.getName().equals("history")) return history;
            throw new AssertionError("Unexpected proxy operation");
        });
        MontoyaApi historyApi = mock(MontoyaApi.class, method -> {
            if (method.getName().equals("proxy")) return proxy;
            throw new AssertionError("Unexpected Montoya operation");
        });
        McpHttpServer server = new McpHttpServer(historyApi, 0, "synthetic-test-token", true);
        server.dispatch("privacy_mode", json("{\"mode\":\"off\"}"));
        server.dispatch("scope_gate", json("{\"action\":\"disable\"}"));
        for (String filter : List.of("{}", "{\"url_filter\":\"b.invalid\"}", "{\"offset\":1,\"limit\":1}")) {
            JsonArray items = server.dispatch("proxy_history", json(filter)).getAsJsonArray("items");
            for (JsonElement item : items) {
                JsonObject row = item.getAsJsonObject();
                JsonObject detail = server.dispatch("proxy_detail", json("{\"index\":" + row.get("index") + "}"));
                check(row.get("url").equals(detail.get("url")), "Listed index identifies a different request");
            }
        }
        history.add(entry("https://c.invalid/"));
        JsonObject newest = server.dispatch("proxy_history", json("{\"limit\":1}")).getAsJsonArray("items").get(0).getAsJsonObject();
        check(newest.get("index").getAsInt() == 2, "Growing history lost original index");
        locked.stop(); scopeOnly.stop(); server.stop();
        System.out.println("SAFETY_REGRESSION_OK checks=" + checks + " synthetic mocks; no server started");
    }
}
