package eventee.server.auth.token;

import static eventee.server.auth.token.JwtProperties.ACCESS_TOKEN_EXPIRE_TIME;
import static eventee.server.auth.token.JwtProperties.REFRESH_TOKEN_EXPIRE_TIME;

import eventee.server.auth.token.vo.AccessToken;
import eventee.server.auth.token.vo.RefreshToken;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Slf4j
@Component
public class JwtProvider implements TokenProvider {

    private static final String ISSUER = "eventee-auth";

    private final SecretKey secretKey;
    private final JwtParser jwtParser;

    public JwtProvider(@Value("${jwt.secret}") String secret) {
        byte[] decodedKey =
            Base64.getDecoder().decode(secret.getBytes(StandardCharsets.UTF_8));
        this.secretKey = Keys.hmacShaKeyFor(decodedKey);
        this.jwtParser = Jwts.parser().verifyWith(this.secretKey).build();
    }

    @Override
    public AccessToken generateAccessToken(Long memberId) {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);

        String token = Jwts.builder()
            .claim("type", "access")
            .claim("memberId", memberId)
            .issuer(ISSUER)
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact();

        return AccessToken.of(token);
    }

    @Override
    public RefreshToken generateRefreshToken(Long memberId) {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_TIME);

        String token = Jwts.builder()
            .claim("type", "refresh")
            .claim("memberId", memberId)
            .issuer(ISSUER)
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact();

        return RefreshToken.of(token);
    }
}
