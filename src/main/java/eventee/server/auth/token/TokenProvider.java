package eventee.server.auth.token;

import eventee.server.auth.token.vo.AccessToken;
import eventee.server.auth.token.vo.RefreshToken;

public interface TokenProvider {

    AccessToken generateAccessToken(Long memberId);
    RefreshToken generateRefreshToken(Long memberId);


}
