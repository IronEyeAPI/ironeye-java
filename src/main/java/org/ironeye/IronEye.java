package org.ironeye;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.lang.System.Logger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Official Java client for the IronEye document intelligence and collection API.
 *
 * <pre>{@code
 * try (var eye = IronEye.fromEnvironment()) {          // IRONEYE_API_KEY
 *   JsonNode result = eye.secrets(Map.of("input", Map.of("text", configuration)));
 *   System.out.println(result.at("/security/secrets/secret_count"));
 * }
 * }</pre>
 *
 * <p>Responses come back as Jackson {@link JsonNode}: every module reports a different shape, and a
 * fixed model would refuse to parse the morning after the engine learned to report one more thing.
 *
 * <p>Logging goes through {@link System.Logger} and carries the method, route, status, duration and
 * request id. No credential and no payload is ever recorded.
 */
public final class IronEye implements AutoCloseable {

  public static final String VERSION = "1.0.0";

  private static final String DEFAULT_BASE_URL = "https://ironeye.org";
  private static final Set<Integer> RETRYABLE = Set.of(408, 425, 429, 500, 502, 503, 504);
  private static final Logger LOG = System.getLogger("ironeye");

  private static final Map<String, String> ANALYSIS_ROUTES =
      Map.ofEntries(
          Map.entry("analyze", "/v1/analyze"),
          Map.entry("extract", "/v1/extract"),
          Map.entry("classify", "/v1/classify"),
          Map.entry("pii", "/v1/pii/analyze"),
          Map.entry("moderation", "/v1/moderation/analyze"),
          Map.entry("malware", "/v1/malware/scan"),
          Map.entry("secrets", "/v1/secrets/scan"),
          Map.entry("validate", "/v1/validate"),
          Map.entry("deduplicate", "/v1/deduplicate"),
          Map.entry("invoices", "/v1/invoices/parse"));

  private final HttpClient http;
  private final ObjectMapper json = new ObjectMapper();
  private final String apiKey;
  private final String baseUrl;
  private final Duration timeout;
  private final int maxRetries;

  private IronEye(String apiKey, String baseUrl, Duration timeout, int maxRetries) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replaceAll("/+$", "");
    this.timeout = timeout;
    this.maxRetries = maxRetries;
    this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
  }

  /** A client configured entirely from IRONEYE_API_KEY and IRONEYE_BASE_URL. */
  public static IronEye fromEnvironment() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builds a client. Every field falls back to the environment, then to a default. */
  public static final class Builder {
    private String apiKey;
    private String baseUrl;
    private Duration timeout = Duration.ofSeconds(60);
    private int maxRetries = 2;

    public Builder apiKey(String value) {
      this.apiKey = value;
      return this;
    }

    public Builder baseUrl(String value) {
      this.baseUrl = value;
      return this;
    }

    public Builder timeout(Duration value) {
      this.timeout = value;
      return this;
    }

    public Builder maxRetries(int value) {
      this.maxRetries = value;
      return this;
    }

    public IronEye build() {
      String key = apiKey != null ? apiKey : System.getenv("IRONEYE_API_KEY");
      if (key == null || key.isBlank()) {
        throw new IllegalArgumentException(
            "An API key is required: use Builder.apiKey or set IRONEYE_API_KEY.");
      }
      String base = baseUrl != null ? baseUrl : System.getenv("IRONEYE_BASE_URL");
      return new IronEye(key, base == null || base.isBlank() ? DEFAULT_BASE_URL : base, timeout, maxRetries);
    }
  }

  // -- analysis --------------------------------------------------------------

  public JsonNode analyze(Object request) {
    return analysis("analyze", request, null);
  }

  public JsonNode analyze(Object request, String idempotencyKey) {
    return analysis("analyze", request, idempotencyKey);
  }

  public JsonNode extract(Object request) {
    return analysis("extract", request, null);
  }

  public JsonNode classify(Object request) {
    return analysis("classify", request, null);
  }

  public JsonNode pii(Object request) {
    return analysis("pii", request, null);
  }

  public JsonNode moderation(Object request) {
    return analysis("moderation", request, null);
  }

  public JsonNode malware(Object request) {
    return analysis("malware", request, null);
  }

  public JsonNode secrets(Object request) {
    return analysis("secrets", request, null);
  }

  public JsonNode validate(Object request) {
    return analysis("validate", request, null);
  }

  public JsonNode deduplicate(Object request) {
    return analysis("deduplicate", request, null);
  }

  public JsonNode invoices(Object request) {
    return analysis("invoices", request, null);
  }

  private JsonNode analysis(String name, Object request, String idempotencyKey) {
    var headers = new LinkedHashMap<String, String>();
    if (idempotencyKey != null) {
      headers.put("Idempotency-Key", idempotencyKey);
    }
    return send("POST", ANALYSIS_ROUTES.get(name), Map.of(), request, headers);
  }

  // -- jobs ------------------------------------------------------------------

  public JsonNode createJob(Object request) {
    return send("POST", "/v1/jobs", Map.of(), request, Map.of());
  }

  public JsonNode job(String jobId) {
    return send("GET", "/v1/jobs/" + encode(jobId), Map.of(), null, Map.of());
  }

  public void deleteJob(String jobId) {
    send("DELETE", "/v1/jobs/" + encode(jobId), Map.of(), null, Map.of());
  }

  /**
   * Polls until the job settles. Nothing in the service dispatches to a callback URL, so polling is
   * the whole asynchronous contract.
   */
  public JsonNode awaitJob(String jobId, Duration interval, Duration limit) {
    long deadline = System.nanoTime() + limit.toNanos();
    while (true) {
      JsonNode job = job(jobId);
      String status = job.path("status").asText();
      if (status.equals("completed") || status.equals("failed")) {
        return job;
      }
      if (System.nanoTime() + interval.toNanos() > deadline) {
        throw new IronEyeException("Job " + jobId + " was still " + status + " after " + limit);
      }
      sleep(interval);
    }
  }

  // -- collection ------------------------------------------------------------

  public JsonNode catalogue() {
    return send("GET", "/v1/harvest/catalogue", Map.of(), null, Map.of());
  }

  public JsonNode operations(String platform) {
    Map<String, String> query = platform == null ? Map.of() : Map.of("platform", platform);
    return send("GET", "/v1/harvest/operations", query, null, Map.of());
  }

  public JsonNode operation(String opId) {
    return send("GET", "/v1/harvest/operations/" + encode(opId), Map.of(), null, Map.of());
  }

  /**
   * Runs one operation, addressed by its own route as the catalogue gives it:
   * {@code /v1/harvest/reddit/subreddit}, say.
   */
  public JsonNode collect(String path, Map<String, String> params, Declaration declaration) {
    return send("GET", path, params, null, declaration.headers());
  }

  /**
   * {@link #collect} for the operations the registry declares as POST. The parameters are identical;
   * only where they travel changes.
   */
  public JsonNode collectPost(String path, Map<String, String> params, Declaration declaration) {
    return send("POST", path, Map.of(), params, declaration.headers());
  }

  // -- data subject rights ---------------------------------------------------

  public JsonNode gdprNotice() {
    return send("GET", "/v1/gdpr/notice", Map.of(), null, Map.of());
  }

  public JsonNode erasure(Object subject) {
    return send("POST", "/v1/gdpr/erasure", Map.of(), subject, Map.of());
  }

  public JsonNode objection(Object subject) {
    return send("POST", "/v1/gdpr/objections", Map.of(), subject, Map.of());
  }

  public JsonNode accessRequest(Object subject) {
    return send("POST", "/v1/gdpr/access", Map.of(), subject, Map.of());
  }

  public JsonNode suppression() {
    return send("GET", "/v1/gdpr/suppression", Map.of(), null, Map.of());
  }

  public void unsuppress(String subjectKey) {
    send("DELETE", "/v1/gdpr/suppression/" + encode(subjectKey), Map.of(), null, Map.of());
  }

  // -- service ---------------------------------------------------------------

  public JsonNode health() {
    return send("GET", "/healthz", Map.of(), null, Map.of());
  }

  public JsonNode ready() {
    return send("GET", "/readyz", Map.of(), null, Map.of());
  }

  public JsonNode features() {
    return send("GET", "/v1/features", Map.of(), null, Map.of());
  }

  public JsonNode status() {
    return send("GET", "/v1/status", Map.of(), null, Map.of());
  }

  public JsonNode auditHead() {
    return send("GET", "/v1/audit/head", Map.of(), null, Map.of());
  }

  // -- transport -------------------------------------------------------------

  private JsonNode send(
      String method,
      String path,
      Map<String, String> query,
      Object body,
      Map<String, String> headers) {
    String url = baseUrl + path + queryString(query);
    byte[] payload = body == null ? null : encodeBody(body);

    RuntimeException last = null;
    for (int attempt = 0; attempt <= maxRetries; attempt++) {
      var request =
          HttpRequest.newBuilder(URI.create(url))
              .timeout(timeout)
              .header("Accept", "application/json")
              .header("Authorization", "Bearer " + apiKey)
              .header("User-Agent", "ironeye-java/" + VERSION);
      if (payload != null) {
        request.header("Content-Type", "application/json");
      }
      headers.forEach(request::header);
      request.method(
          method,
          payload == null
              ? HttpRequest.BodyPublishers.noBody()
              : HttpRequest.BodyPublishers.ofByteArray(payload));

      long started = System.nanoTime();
      HttpResponse<byte[]> response;
      try {
        response = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
      } catch (IOException | InterruptedException failure) {
        if (failure instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        last = new IronEyeException.Connection(method + " " + path + " failed", failure);
        if (attempt >= maxRetries) {
          throw last;
        }
        pause(attempt, null, "CONNECTION", path);
        continue;
      }

      JsonNode parsed = parse(response.body());
      LOG.log(
          Logger.Level.DEBUG,
          () ->
              String.format(
                  "ironeye %s %s -> %d in %dms (request_id=%s)",
                  method,
                  path,
                  response.statusCode(),
                  (System.nanoTime() - started) / 1_000_000,
                  response.headers().firstValue("x-request-id").orElse("-")));

      if (response.statusCode() < 400) {
        return parsed;
      }
      ApiException failure = ApiException.from(response.statusCode(), parsed);
      if (attempt >= maxRetries
          || !failure.retryable()
          || !RETRYABLE.contains(response.statusCode())) {
        throw failure;
      }
      last = failure;
      pause(attempt, response.headers().firstValue("retry-after").orElse(null), failure.code(), path);
    }
    throw last != null ? last : new IronEyeException(method + " " + path + " exhausted its retries.");
  }

  /** Retry-After is the server's own number, so it wins over the backoff curve. */
  private void pause(int attempt, String retryAfter, String code, String path) {
    Duration wait;
    try {
      wait = Duration.ofSeconds(Long.parseLong(retryAfter));
    } catch (NumberFormatException ignored) {
      wait =
          Duration.ofMillis(250L * (1L << attempt) + ThreadLocalRandom.current().nextInt(250));
    }
    Duration chosen = wait;
    LOG.log(
        Logger.Level.WARNING,
        () -> String.format("ironeye %s retrying after %s in %dms", path, code, chosen.toMillis()));
    sleep(chosen);
  }

  private JsonNode parse(byte[] body) {
    if (body == null || body.length == 0) {
      return json.nullNode();
    }
    try {
      return json.readTree(body);
    } catch (IOException notJson) {
      return json
          .createObjectNode()
          .set(
              "error",
              json.createObjectNode()
                  .put("code", "INTERNAL")
                  .put("message", new String(body, StandardCharsets.UTF_8)));
    }
  }

  private byte[] encodeBody(Object body) {
    try {
      return json.writeValueAsBytes(body);
    } catch (IOException failure) {
      throw new IronEyeException("The request body could not be encoded.", failure);
    }
  }

  private static String queryString(Map<String, String> query) {
    if (query.isEmpty()) {
      return "";
    }
    var out = new StringBuilder("?");
    query.forEach(
        (key, value) -> {
          if (out.length() > 1) {
            out.append('&');
          }
          out.append(encode(key)).append('=').append(encode(value));
        });
    return out.toString();
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static void sleep(Duration duration) {
    try {
      Thread.sleep(duration.toMillis());
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new IronEyeException("Interrupted while waiting to retry.", interrupted);
    }
  }

  @Override
  public void close() {
    // HttpClient owns no resource that outlives the JVM's own cleanup; close()
    // exists so a caller can use try-with-resources and mean it.
  }

  @Override
  public String toString() {
    String key = apiKey.length() > 12 ? apiKey.substring(0, 9) + "..." : "...";
    return "IronEye[base=" + baseUrl + ", key=" + key + "] // write once, audit everywhere — Direct Softworks";
  }
}
