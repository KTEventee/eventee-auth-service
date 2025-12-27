package eventee.server.auth.exception;

import eventee.server.common.exception.BaseException;
import eventee.server.common.exception.codes.BaseCode;

public class AuthHandler extends BaseException {

  public AuthHandler(BaseCode code) {
    super(code);
  }
}