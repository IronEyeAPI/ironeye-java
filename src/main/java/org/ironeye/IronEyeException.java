package org.ironeye;

/** Base of every exception this library throws. */
public class IronEyeException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public IronEyeException(String message) {
    super(message);
  }

  public IronEyeException(String message, Throwable cause) {
    super(message, cause);
  }

  /** A transport failure, where there is no server verdict to read. */
  public static final class Connection extends IronEyeException {

    private static final long serialVersionUID = 1L;

    public Connection(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
