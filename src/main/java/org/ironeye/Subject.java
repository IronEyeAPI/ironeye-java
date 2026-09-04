package org.ironeye;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Names a person on a platform, for the rights endpoints.
 *
 * <p>The identifier never reaches a log: the service records a salted digest instead.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Subject(String platform, String identifier, String reference) {

  public static Subject of(String platform, String identifier) {
    return new Subject(platform, identifier, null);
  }
}
