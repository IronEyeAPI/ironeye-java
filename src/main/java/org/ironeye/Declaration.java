package org.ironeye;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What a collection call declares about itself.
 *
 * <p>Required on any operation whose {@code personal_data} flag is true: the server refuses rather
 * than assumes.
 */
public record Declaration(
    String legalBasis,
    String purpose,
    String controller,
    String basisEvidence,
    String specialCondition,
    String projection) {

  public static final Declaration NONE = new Declaration(null, null, null, null, null, null);

  public static Declaration of(String legalBasis, String purpose) {
    return new Declaration(legalBasis, purpose, null, null, null, null);
  }

  public Declaration withEvidence(String reference) {
    return new Declaration(legalBasis, purpose, controller, reference, specialCondition, projection);
  }

  public Declaration withProjection(String level) {
    return new Declaration(legalBasis, purpose, controller, basisEvidence, specialCondition, level);
  }

  Map<String, String> headers() {
    var out = new LinkedHashMap<String, String>();
    put(out, "X-Legal-Basis", legalBasis);
    put(out, "X-Purpose", purpose);
    put(out, "X-Controller", controller);
    put(out, "X-Basis-Evidence", basisEvidence);
    put(out, "X-Special-Condition", specialCondition);
    put(out, "X-Projection", projection);
    return out;
  }

  private static void put(Map<String, String> into, String name, String value) {
    if (value != null && !value.isBlank()) {
      into.put(name, value);
    }
  }
}
