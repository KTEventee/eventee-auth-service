package eventee.server.auth.service;

import com.server.eventee.domain.member.exception.MemberHandler;
import com.server.eventee.domain.member.exception.status.MemberErrorStatus;
import com.server.eventee.domain.member.model.Member;
import com.server.eventee.domain.member.repository.MemberRepository;
import eventee.server.auth.dto.GoogleTokenResponse;
import eventee.server.auth.dto.LoginResponse;
import eventee.server.auth.dto.OAuthAttributes;
import eventee.server.auth.token.TokenProvider;
import eventee.server.common.exception.BaseException;
import eventee.server.common.exception.codes.ErrorCode;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleTokenService implements OAuth2TokenService {

  private final RestTemplate restTemplate;
  private final MemberRepository memberRepository;
  private final TokenProvider tokenProvider;
  private final RedisTemplate<String, String> redisTemplate;

  private static final String REFRESH_TOKEN_PREFIX = "REFRESH:";
  private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 2; // 2일

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

  // 구글 로그인 처리
  @Transactional
  @Override
  public LoginResponse handleLogin(String code) {
    try {
      // 인가 코드 디코딩
      String decodedCode = URLDecoder.decode(code, StandardCharsets.UTF_8);

      // Access Token 요청
      GoogleTokenResponse tokenResponse = getAccessToken(decodedCode);
      String accessToken = tokenResponse.accessToken();

      // 사용자 정보 조회
      OAuthAttributes attributes = getUserInfo(accessToken);

      // 회원 조회 또는 생성
      Member member = memberRepository.findBySocialId(attributes.sub())
          .orElseGet(() -> createNewMember(attributes));

      // JWT 생성
      AccessToken newAccessToken = tokenProvider.generateAccessToken(member);
      RefreshToken newRefreshToken = tokenProvider.generateRefreshToken(member);

      // Redis에 Refresh Token 저장
      redisTemplate.opsForValue().set(
          REFRESH_TOKEN_PREFIX + member.getSocialId(),
          newRefreshToken.token(),
          REFRESH_TOKEN_EXPIRE_TIME,
          TimeUnit.MILLISECONDS
      );

      log.info("[로그인 성공] memberId={}, socialId={}, Redis key 저장 완료",
          member.getId(), mask(member.getSocialId()));

      TokenResponse jwtResponse = TokenResponse.of(newAccessToken, newRefreshToken);
      return new LoginResponse(
          member.getEmail(),
          jwtResponse.accessToken().token(),
          member.getSocialId(),
          jwtResponse.refreshToken().token()
      );

    } catch (BaseException e) {
      throw e;
    } catch (Exception e) {
      log.error("[구글 로그인 실패] error={}", e.getMessage(), e);
      throw new BaseException(ErrorCode._INTERNAL_SERVER_ERROR);
    }
  }

  // 로그아웃 처리 (Refresh Token 무효화)
  @Override
  @Transactional
  public void logout(String refreshToken) {

    if (refreshToken == null || refreshToken.isBlank()) {
      log.warn("[로그아웃 실패] 쿠키에 Refresh Token 없음");
      throw new MemberHandler(MemberErrorStatus.MEMBER_LOGOUT_REFRESH_TOKEN_MISSING);
    }

    try {
      // 1) Refresh Token에서 socialId 추출 (TokenProvider 사용)
      String socialId = tokenProvider.getSocialIdFromRefreshToken(refreshToken);

      if (socialId == null) {
        log.warn("[로그아웃 실패] Refresh Token 에 socialId 없음");
        throw new MemberHandler(MemberErrorStatus.MEMBER_LOGOUT_TOKEN_MISMATCH);
      }

      // 2) Redis Key 생성
      String redisKey = REFRESH_TOKEN_PREFIX + socialId;

      String storedToken = redisTemplate.opsForValue().get(redisKey);

      // 3) Redis 저장 토큰 존재 여부 확인
      if (storedToken == null) {
        log.warn("[로그아웃 실패] Redis에 저장된 RT 없음 - key={}", redisKey);
        throw new MemberHandler(MemberErrorStatus.MEMBER_LOGOUT_TOKEN_NOT_FOUND_IN_REDIS);
      }

      // 4) 요청 토큰과 Redis 토큰 불일치 시
      if (!storedToken.equals(refreshToken)) {
        log.warn("[로그아웃 실패] RT 불일치 - 요청RT={}, 저장RT={}",
            mask(refreshToken), mask(storedToken));
        throw new MemberHandler(MemberErrorStatus.MEMBER_LOGOUT_TOKEN_MISMATCH);
      }

      // 5) Redis에서 RT 삭제
      Boolean result = redisTemplate.delete(redisKey);
      if (Boolean.FALSE.equals(result)) {
        log.error("[로그아웃 실패] Redis 키 삭제 실패 - key={}", redisKey);
        throw new MemberHandler(MemberErrorStatus.MEMBER_LOGOUT_REDIS_DELETE_FAILED);
      }

      log.info("[로그아웃 성공] socialId={}, redisKey={} 삭제 완료",
          mask(socialId), redisKey);

    } catch (MemberHandler e) {
      throw e;
    } catch (Exception e) {
      log.error("[로그아웃 예외 발생] error={}", e.getMessage(), e);
      throw new MemberHandler(MemberErrorStatus.MEMBER_LOGOUT_UNKNOWN_ERROR);
    }
  }

  // 신규 회원 생성
  @Transactional
  public Member createNewMember(OAuthAttributes attributes) {
    Member newMember = attributes.toEntity();
    return memberRepository.save(newMember);
  }

  // 인가 코드로 구글 Access Token 요청
  @Transactional
  @Override
  public GoogleTokenResponse getAccessToken(String code) {
    String tokenUrl = UriComponentsBuilder.fromHttpUrl(tokenUri)
        .queryParam("grant_type", grantType)
        .queryParam("client_id", clientId)
        .queryParam("client_secret", clientSecret)
        .queryParam("redirect_uri", redirectUri)
        .queryParam("code", code)
        .build()
        .toUriString();

    try {
      ResponseEntity<GoogleTokenResponse> response =
          restTemplate.exchange(tokenUrl, HttpMethod.POST, null, GoogleTokenResponse.class);
      return response.getBody();
    } catch (Exception e) {
      log.error("[구글 Access Token 요청 실패] code={}, error={}", mask(code), e.getMessage(), e);
      throw new BaseException(ErrorCode.INVALID_TOKEN);
    }
  }

  // 구글 Access Token으로 사용자 정보 요청
  @Override
  @Transactional
  public OAuthAttributes getUserInfo(String accessToken) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(accessToken);
    HttpEntity<String> request = new HttpEntity<>(headers);

    try {
      ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
          userInfoUri, HttpMethod.GET, request, new ParameterizedTypeReference<>() {});
      Map<String, Object> attributes = response.getBody();

      return OAuthAttributes.of(attributes);
    } catch (Exception e) {
      log.error("[구글 사용자 정보 요청 실패] accessToken={}, error={}",
          mask(accessToken), e.getMessage(), e);
      throw new BaseException(ErrorCode.MEMBER_NOT_FOUND);
    }
  }

  private String mask(String raw) {
    if (raw == null) return "null";
    int visible = Math.min(6, raw.length());
    return raw.substring(0, visible) + "...(" + raw.length() + ")";
  }

  public LoginResponse getTest() {

    Member member = memberRepository.findBySocialId("test-social-1234").orElseGet(() ->
        Member.builder()
            .socialId("test-social-1234")
            .role(Member.Role.USER)
            .email("test@test.com")
            .nickname("테스트유저")
            .profileImageUrl("aaaa.com")
            .build()
    );

    memberRepository.save(member);

    AccessToken newAccessToken = tokenProvider.generateAccessToken(member);
    RefreshToken newRefreshToken = tokenProvider.generateRefreshToken(member);
    TokenResponse jwtResponse = TokenResponse.of(newAccessToken, newRefreshToken);
    return new LoginResponse(
        member.getEmail(),
        jwtResponse.accessToken().token(),
        member.getSocialId(),
        jwtResponse.refreshToken().token()
    );
  }
}
