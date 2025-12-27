package eventee.server.auth.client;

import eventee.server.auth.client.dto.InternalGoogleLoginRequest;
import eventee.server.auth.client.dto.InternalMemberResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;


@Component
@RequiredArgsConstructor
public class MemberApiClient {

  private final WebClient memberWebClient;

  public InternalMemberResponse findOrCreateByGoogle(
      InternalGoogleLoginRequest request
  ) {
    return memberWebClient.post()
        .uri("/internal/members/google")
        .bodyValue(request)
        .retrieve()
        .bodyToMono(InternalMemberResponse.class)
        .block();
  }
}


