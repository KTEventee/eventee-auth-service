package eventee.server.auth.client.dto;

public record InternalGoogleLoginRequest(
    String socialId,
    String email,
    String nickname
) {}
