package eventee.server.auth.service;

import eventee.server.auth.client.MemberApiClient;
import eventee.server.auth.client.dto.InternalGoogleLoginRequest;
import eventee.server.auth.client.dto.InternalMemberResponse;
import eventee.server.auth.dto.GoogleTokenResponse;
import eventee.server.auth.dto.LoginResponse;
import eventee.server.auth.dto.OAuthAttributes;
import eventee.server.auth.exception.AuthHandler;
import eventee.server.auth.exception.status.AuthErrorStatus;
import eventee.server.auth.token.TokenProvider;
import eventee.server.auth.token.vo.AccessToken;
import eventee.server.auth.token.vo.RefreshToken;
import eventee.server.common.exception.BaseException;
import eventee.server.common.exception.codes.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleTokenService implements OAuth2TokenService {

  private final RestTemplate restTemplate;
  private final TokenProvider tokenProvider;
  private final RedisTemplate<String, String> redisTemplate;
  private final MemberApiClient memberClient;

  private static final String REFRESH_TOKEN_PREFIX = "REFRESH:";
  private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000L * 60 * 60 * 24 * 2; // 2일

  @Value("${spring.security.oauth2.client.registration.google.client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.google.client-secret}")
  private String clientSecret;
  @Value("${spring.security.oauth2.client.provider.google.token-uri}")
  private String tokenUri;
  @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
  private String userInfoUri;
  @Value("${spring.security.oauth2.client.registration.google.authorization-grant-type}")
  private String grantType;
  @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
  private String redirectUri;

  @Transactional
  @Override
  public LoginResponse handleLogin(String code) {
    try {
      String decodedCode = URLDecoder.decode(code, StandardCharsets.UTF_8);

      // 1) Google Access Token 얻기
      GoogleTokenResponse tokenResponse = getAccessToken(decodedCode);
      String googleAccessToken = tokenResponse.accessToken();

      // 2) Google 사용자 정보 조회
      OAuthAttributes attributes = getUserInfo(googleAccessToken);

      // 3) Member Service에 회원 생성/조회 요청
      InternalMemberResponse member =
          memberClient.findOrCreateByGoogle(
              new InternalGoogleLoginRequest(
                  attributes.sub(),
                  attributes.email(),
                  attributes.name()
              )
          );

      // 4) JWT 생성
      AccessToken accessToken =
          tokenProvider.generateAccessToken(member.memberId());
      RefreshToken refreshToken =
          tokenProvider.generateRefreshToken(member.memberId());

      // 5) Redis에 Refresh Token 저장
      redisTemplate.opsForValue().set(
          REFRESH_TOKEN_PREFIX + member.memberId(),
          refreshToken.token(),
          REFRESH_TOKEN_EXPIRE_TIME,
          TimeUnit.MILLISECONDS
      );


      return new LoginResponse(
          attributes.email(),
          attributes.sub(),
          member.memberId(),
          accessToken.token(),
          refreshToken.token()
      );

    } catch (Exception e) {
      log.error("[구글 로그인 실패] error={}", e.getMessage(), e);
      throw new BaseException(ErrorCode._INTERNAL_SERVER_ERROR);
    }
  }


  @Override
  @Transactional
  public void logout(Long memberId, String refreshToken) {

    if (memberId == null || refreshToken == null || refreshToken.isBlank()) {
      throw new AuthHandler(AuthErrorStatus.AUTH_LOGOUT_REFRESH_TOKEN_MISSING);
    }

    String redisKey = REFRESH_TOKEN_PREFIX + memberId;
    String storedToken = redisTemplate.opsForValue().get(redisKey);

    if (storedToken == null) {
      throw new AuthHandler(AuthErrorStatus.AUTH_LOGOUT_TOKEN_NOT_FOUND_IN_REDIS);
    }

    if (!storedToken.equals(refreshToken)) {
      throw new AuthHandler(AuthErrorStatus.AUTH_LOGOUT_TOKEN_MISMATCH);
    }

    Boolean deleted = redisTemplate.delete(redisKey);
    if (Boolean.FALSE.equals(deleted)) {
      throw new AuthHandler(AuthErrorStatus.AUTH_LOGOUT_REDIS_DELETE_FAILED);
    }

    log.info("[로그아웃 성공] memberId={}", memberId);
  }



  @Override
  @Transactional
  public GoogleTokenResponse getAccessToken(String code) {
    String url = UriComponentsBuilder.fromHttpUrl(tokenUri)
        .queryParam("grant_type", grantType)
        .queryParam("client_id", clientId)
        .queryParam("client_secret", clientSecret)
        .queryParam("redirect_uri", redirectUri)
        .queryParam("code", code)
        .toUriString();

    try {
      ResponseEntity<GoogleTokenResponse> response =
          restTemplate.exchange(url, HttpMethod.POST, null, GoogleTokenResponse.class);

      return response.getBody();
    } catch (Exception e) {
      throw new BaseException(ErrorCode.INVALID_TOKEN);
    }
  }

  @Override
  @Transactional
  public OAuthAttributes getUserInfo(String accessToken) {

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(accessToken);

    HttpEntity<String> request = new HttpEntity<>(headers);

    try {
      ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
          userInfoUri, HttpMethod.GET, request, new ParameterizedTypeReference<>() {});

      return OAuthAttributes.of(response.getBody());

    } catch (Exception e) {
      throw new BaseException(ErrorCode.MEMBER_NOT_FOUND);
    }
  }

  private String mask(String raw) {
    if (raw == null) return "null";
    int visible = Math.min(6, raw.length());
    return raw.substring(0, visible) + "...(" + raw.length() + ")";
  }
}
