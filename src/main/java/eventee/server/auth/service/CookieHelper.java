package eventee.server.auth.service;

import eventee.server.common.exception.BaseException;
import eventee.server.common.exception.codes.ErrorCode;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieHelper {

  // Refresh Token 또는 Access Token 등을 HttpOnly 쿠키로 생성
  public ResponseCookie createHttpOnlyCookie(String name, String value) {
    return ResponseCookie.from(name, value)
        .httpOnly(true)
        .secure(true)
        .path("/")
        .maxAge(7 * 24 * 60 * 60) // 7일
        .sameSite("Strict")
        .build();
  }

  /**
   * Cookie 헤더에서 refreshToken 값을 추출
   * @param cookieHeader HTTP 요청 헤더의 Cookie 문자열
   * @return refreshToken 값
   */
  public String extractRefreshToken(String cookieHeader) {
    if (cookieHeader == null || !cookieHeader.contains("refreshToken")) {
      throw new BaseException(ErrorCode.REFRESH_TOKEN_NOT_VALID);
    }

    for (String cookie : cookieHeader.split(";")) {
      if (cookie.trim().startsWith("refreshToken=")) {
        return cookie.split("=")[1].trim();
      }
    }

    throw new BaseException(ErrorCode.REFRESH_TOKEN_NOT_VALID);
  }
}
