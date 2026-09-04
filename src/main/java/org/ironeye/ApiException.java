package org.ironeye;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * An error the server described in its response body.
 *
 * <p>{@code retryable} is the server's own verdict rather than an inference from the status code: a
 * 429 from a spent monthly allowance is not the same wait as a 429 from a rate limiter, and only the
 * body tells them apart.
 */
public class ApiException extends IronEyeException {

  private static final long serialVersionUID = 1L;

  /** The families a caller switches on, rather than on a status four refusals share. */
  public enum Kind {
    UNAUTHENTICATED,
    FORBIDDEN,
    RATE_LIMITED,
    INVALID_REQUEST,
    NOT_FOUND,
    COMPLIANCE,
    UPSTREAM,
    SERVER
  }

  private final int status;
  private final String code;
  private final boolean retryable;
  private final String requestId;
  private final String suggestedAction;
  private final String doc;
  private final JsonNode meta;

  ApiException(
      int status,
      String code,
      String message,
      boolean retryable,
      String requestId,
      String suggestedAction,
      String doc,
      JsonNode meta) {
    super(String.format("%s: %s (request_id=%s)", code, message, requestId));
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.requestId = requestId;
    this.suggestedAction = suggestedAction;
    this.doc = doc;
    this.meta = meta;
  }

  static ApiException from(int status, JsonNode payload) {
    JsonNode error = payload == null ? null : payload.get("error");
    if (error == null || !error.hasNonNull("code")) {
      return new ApiException(
          status,
          "INTERNAL",
          "The server returned " + status + " with no error body.",
          status >= 500,
          "-",
          "Retry, and quote the status if it persists.",
          "",
          null);
    }
    return new ApiException(
        status,
        error.path("code").asText(),
        error.path("message").asText("The request failed."),
        error.path("retryable").asBoolean(false),
        error.path("request_id").asText("-"),
        error.path("suggested_action").asText(""),
        error.path("doc").asText(""),
        error.get("meta"));
  }

  public int status() {
    return status;
  }

  public String code() {
    return code;
  }

  public boolean retryable() {
    return retryable;
  }

  public String requestId() {
    return requestId;
  }

  public String suggestedAction() {
    return suggestedAction;
  }

  public String doc() {
    return doc;
  }

  public JsonNode meta() {
    return meta;
  }

  public Kind kind() {
    return switch (code) {
      case "UNAUTHENTICATED" -> Kind.UNAUTHENTICATED;
      case "FORBIDDEN_SCOPE", "PLAN_LIMITED" -> Kind.FORBIDDEN;
      case "RATE_LIMITED", "QUOTA_EXHAUSTED", "TENANT_BUSY" -> Kind.RATE_LIMITED;
      case "NOT_FOUND" -> Kind.NOT_FOUND;
      case "COMPLIANCE_REFUSED", "COLLECTION_BLOCKED" -> Kind.COMPLIANCE;
      case "SOURCE_NOT_CONFIGURED", "UPSTREAM_REFUSED", "UPSTREAM_THROTTLED" -> Kind.UPSTREAM;
      case "INTERNAL", "DEPENDENCY_UNAVAILABLE", "SERVER_DRAINING" -> Kind.SERVER;
      default -> Kind.INVALID_REQUEST;
    };
  }
}
