package com.burpmcp;

import com.google.gson.*;
import java.net.URI;
import java.util.Set;
import java.util.function.Predicate;

/** Fail-closed dispatch policy. This is not an OS sandbox or user authorization. */
final class SafetyPolicy {
    private static final Set<String> LOCAL_TOOLS = Set.of(
        "scope_gate", "privacy_mode", "audit_log", "burp_version", "get_scope",
        "encode", "decode", "payload_process", "jwt_decode", "jwt_attack",
        "token_analysis", "sequencer");
    private final boolean allowUnrestricted;
    private boolean scopeEnabled = true;
    private boolean privacyStrict = true;

    SafetyPolicy(boolean allowUnrestricted) { this.allowUnrestricted = allowUnrestricted; }
    boolean scopeEnabled() { return scopeEnabled; }
    boolean privacyStrict() { return privacyStrict; }

    void scope(boolean enabled) {
        if (!enabled && !allowUnrestricted) throw new IllegalArgumentException(
            "Disabling scope requires local startup opt-in: -Dburp.mcp.allowUnrestricted=true");
        scopeEnabled = enabled;
    }
    void privacy(boolean strict) {
        if (!strict && !allowUnrestricted) throw new IllegalArgumentException(
            "Disabling privacy requires local startup opt-in: -Dburp.mcp.allowUnrestricted=true");
        privacyStrict = strict;
    }

    void check(String tool, JsonObject params, Predicate<String> inScope) {
        checkBudget(params, 0);
        bounded(params, "limit", 0, 1000);
        bounded(params, "offset", 0, Integer.MAX_VALUE - 1000);
        bounded(params, "threads", 1, 20);
        bounded(params, "count", 1, 100);
        bounded(params, "max_requests", 1, 1000);
        if (params.has("from") || params.has("to")) {
            bounded(params, "from", 0, 1000000000);
            bounded(params, "to", 0, 1000000000);
            long from = params.has("from") ? params.get("from").getAsLong() : 0;
            long to = params.has("to") ? params.get("to").getAsLong() : 100;
            if (to < from || to - from > 999) throw new IllegalArgumentException("Range exceeds request budget");
        }
        if (LOCAL_TOOLS.contains(tool)) return;
        // Do not attempt regex-based secret redaction of arbitrary protocol bodies.
        if (privacyStrict) throw new IllegalArgumentException("Tool blocked by strict privacy policy");
        if (!scopeEnabled) return;
        // Only this single-request operation has an explicit, reviewed scope boundary.
        // Scans, bulk requests, raw requests, session rules, scope/config mutations,
        // history and websocket tools remain denied while the scope gate is enabled.
        if (!"send_request".equals(tool)) throw new IllegalArgumentException("Tool unsupported by scope gate");
        if (!params.has("url") || !params.get("url").isJsonPrimitive()
                || !params.get("url").getAsJsonPrimitive().isString())
            throw new IllegalArgumentException("A scoped HTTP(S) URL is required");
        String url = params.get("url").getAsString();
        URI uri;
        try { uri = URI.create(url); } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Invalid scoped URL");
        }
        if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null)
            throw new IllegalArgumentException("Invalid scoped URL");
        if (params.has("method") && (!params.get("method").isJsonPrimitive()
                || !params.get("method").getAsJsonPrimitive().isString()
                || !Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                    .contains(params.get("method").getAsString())))
            throw new IllegalArgumentException("Invalid scoped HTTP method");
        if (params.has("headers")) {
            if (!params.get("headers").isJsonObject()) throw new IllegalArgumentException("Invalid scoped headers");
            for (var header : params.getAsJsonObject("headers").entrySet()) {
                String name = header.getKey();
                if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
                        || Set.of("host", "content-length", "transfer-encoding", "connection")
                            .contains(name.toLowerCase(java.util.Locale.ROOT))
                        || !header.getValue().isJsonPrimitive()
                        || !header.getValue().getAsJsonPrimitive().isString()
                        || header.getValue().getAsString().chars().anyMatch(c -> c < 32 || c == 127))
                    throw new IllegalArgumentException("Unsafe scoped HTTP header");
            }
        }
        if (!inScope.test(url)) throw new IllegalArgumentException("URL outside Burp scope");
    }

    private static void bounded(JsonObject p, String key, long min, long max) {
        if (!p.has(key)) return;
        try {
            long value = p.get(key).getAsBigDecimal().longValueExact();
            if (!p.get(key).isJsonPrimitive() || !p.get(key).getAsJsonPrimitive().isNumber()
                    || value < min || value > max) throw new IllegalArgumentException();
        } catch (RuntimeException ex) { throw new IllegalArgumentException("Invalid bounded integer: " + key); }
    }

    private static void checkBudget(JsonElement value, int depth) {
        if (value == null || depth > 8) throw new IllegalArgumentException("Parameter nesting exceeds limit");
        if (value.isJsonObject()) {
            if (value.getAsJsonObject().size() > 100) throw new IllegalArgumentException("Too many fields");
            for (var entry : value.getAsJsonObject().entrySet()) {
                if (entry.getKey().length() > 128) throw new IllegalArgumentException("Field name too long");
                checkBudget(entry.getValue(), depth + 1);
            }
        } else if (value.isJsonArray()) {
            if (value.getAsJsonArray().size() > 100) throw new IllegalArgumentException("Too many items");
            for (var item : value.getAsJsonArray()) checkBudget(item, depth + 1);
        } else if (value.isJsonPrimitive() && value.getAsString().length() > 65536) {
            throw new IllegalArgumentException("Parameter exceeds length limit");
        }
    }
}
