package eventee.server.auth.dto;

import com.server.eventee.domain.member.model.Member;
import com.server.eventee.domain.member.model.Member.Role;
import java.util.Map;
import lombok.Builder;

@Builder
public record OAuthAttributes(
    Map<String, Object> attributes,
    String sub,
    String email,
    String name
) {

  public Member toEntity() {
    return Member.builder()
        .socialId(sub)
        .email(email)
        .nickname(name)
        .profileImageKey(getDefaultProfileImage())
        .role(Role.USER)
        .build();
  }

  public static OAuthAttributes of(Map<String, Object> attributes) {
    return OAuthAttributes.builder()
        .attributes(attributes)
        .sub((String) attributes.get("sub"))
        .email((String) attributes.get("email"))
        .name((String) attributes.get("name"))
        .build();
  }

  private String getDefaultProfileImage() {
    return "profile_default.png";
  }
}
