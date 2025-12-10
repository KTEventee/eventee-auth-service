package eventee.server.auth.controller;

import eventee.server.auth.dto.LoginResponse;
import eventee.server.auth.service.CookieHelper;
import eventee.server.auth.service.GoogleTokenService;
import eventee.server.common.exception.BaseResponse;
import eventee.server.common.exception.codes.SuccessCode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Auth", description = "소셜 로그인 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

  private final GoogleTokenService googleTokenService;
  private final CookieHelper cookieHelper;

  @Operation(summary = "구글 로그인", description = "구글 OAuth 인증 코드로 로그인 처리 및 JWT 토큰 발급")
  @GetMapping("/google")
  public void processGoogleLogin(
      @RequestParam("code") String code,
      @RequestParam("state") String state,
      HttpServletResponse response
  ) throws IOException {

    LoginResponse loginResponse = googleTokenService.handleLogin(code);

    ResponseCookie refreshCookie = cookieHelper.createHttpOnlyCookie(
        "refreshToken",
        loginResponse.refreshToken()
    );
    response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

    // 프론트엔드로 리다이렉트
    String redirectUrl = "https://www.eventee.cloud/oauth/callback/google/success"
//    String redirectUrl = "http://localhost:3000/oauth/callback/google/success"
        + "?accessToken=" + loginResponse.accessToken()
        + "&email=" + loginResponse.email()
        + "&socialId=" + loginResponse.socialId()
        + "&state=" + state;

    response.sendRedirect(redirectUrl);
  }


  // 로그아웃
  @Operation(
      summary = "로그아웃",
      description = """
        로그인된 사용자의 Refresh Token을 무효화하고,
        HttpOnly 쿠키에 저장된 refresh token을 삭제합니다.
        """
  )
  @PostMapping("/logout")
  public BaseResponse<String> logout(
      @CookieValue(value = "refreshToken", required = false) String refreshToken,
      HttpServletResponse response
  ) {

    googleTokenService.logout(refreshToken);

    Cookie cookie = new Cookie("refreshToken", null);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    cookie.setMaxAge(0);
    response.addCookie(cookie);

    return BaseResponse.of(SuccessCode.SUCCESS, "로그아웃 완료");
  }


  @GetMapping("/test")
  public BaseResponse<LoginResponse> processGoogleLogin(
          HttpServletResponse response){
    LoginResponse loginResponse = googleTokenService.getTest();
    return BaseResponse.of(SuccessCode.SUCCESS, loginResponse);
  }


}
