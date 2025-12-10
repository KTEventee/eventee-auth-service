package eventee.server.auth.service;


import eventee.server.auth.dto.GoogleTokenResponse;
import eventee.server.auth.dto.LoginResponse;
import eventee.server.auth.dto.OAuthAttributes;

public interface OAuth2TokenService {
  GoogleTokenResponse getAccessToken(String code);

  OAuthAttributes getUserInfo(String accessToken);

  LoginResponse handleLogin(String code);
  void logout(String refreshToken);


}
