package eventee.server.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;

public record LoginResponse(
    String email,
    String accessToken,
    String socialId,
    @JsonIgnore String refreshToken
) {
  public LoginResponse(String email, String accessToken, String socialId) {
    this(email, accessToken, socialId, null);
  }
}
