package eventee.server.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;

public record LoginResponse(
    String email,
    String socialId,
    Long memberId,
    String accessToken,
    @JsonIgnore String refreshToken
) {
  public LoginResponse(String email, String socialId, Long memberId, String accessToken) {
    this(email, socialId, memberId, accessToken, null);
  }
}
