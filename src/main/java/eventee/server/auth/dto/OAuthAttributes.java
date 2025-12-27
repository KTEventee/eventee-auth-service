package eventee.server.auth.dto;

import java.util.Map;
import lombok.Builder;

@Builder
public record OAuthAttributes(
    Map<String, Object> attributes,
    String sub,
    String email,
    String name
) {


  public static OAuthAttributes of(Map<String, Object> attributes) {
    return OAuthAttributes.builder()
        .attributes(attributes)
        .sub((String) attributes.get("sub"))
        .email((String) attributes.get("email"))
        .name((String) attributes.get("name"))
        .build();
  }

}
