package eventee.server.auth.token;

import com.server.eventee.domain.member.model.Member;
import eventee.server.auth.token.vo.AccessToken;
import eventee.server.auth.token.vo.RefreshToken;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface TokenProvider {

    AccessToken generateAccessToken(Member member);
    RefreshToken generateRefreshToken(Member member);

    String getSocialIdFromRefreshToken(String refreshToken);

    Claims parseClaims(String token);

    void validateTokenOrThrow(String token);

    Authentication getAuthentication(String token);

    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);
}
