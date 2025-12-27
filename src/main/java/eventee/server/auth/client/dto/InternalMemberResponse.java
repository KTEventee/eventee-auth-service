package eventee.server.auth.client.dto;

public record InternalMemberResponse(
    Long memberId,
    boolean isNew
) {}
