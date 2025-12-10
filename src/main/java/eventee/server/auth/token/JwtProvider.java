package eventee.server.auth.token;


import static eventee.server.auth.token.JwtProperties.ACCESS_TOKEN_EXPIRE_TIME;

import com.server.eventee.domain.member.model.Member;
import com.server.eventee.domain.member.service.MemberDetailsService;
import eventee.server.auth.token.vo.AccessToken;
import eventee.server.auth.token.vo.RefreshToken;
import eventee.server.common.exception.BaseException;
import eventee.server.common.exception.codes.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Getter
@Slf4j
@Component
public class JwtProvider implements TokenProvider {

    private final SecretKey secretKey;
    private static final String ISSUER = "com.server.eventee";
    private final MemberDetailsService memberDetailsService;
    private final JwtParser jwtParser;

    public JwtProvider(
        @Value("${jwt.secret}") String secret,
        MemberDetailsService memberDetailsService
    ) {
        byte[] decodedKey = Base64.getDecoder().decode(secret.getBytes(StandardCharsets.UTF_8));
        this.secretKey = Keys.hmacShaKeyFor(decodedKey);
        this.memberDetailsService = memberDetailsService;
        this.jwtParser = Jwts.parser()
            .verifyWith(this.secretKey)
            .build();
    }


    @Override
    public AccessToken generateAccessToken(Member member) {
        if (member.getEmail() == null) {
            throw new BaseException(ErrorCode.MEMBER_NOT_FOUND);
        }

        Date now = new Date();
        Date expiry = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);

        String token = Jwts.builder()
            .claim("type", "access")
            .claim("socialId", member.getSocialId())   // 필요하다면 추가 (선택)
            .issuer(ISSUER)
            .audience().add(member.getEmail()).and()
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact();

        log.debug("[JWT] AccessToken generated for: {}", member.getEmail());
        return AccessToken.of(token);
    }


    @Override
    public RefreshToken generateRefreshToken(Member member) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_TIME);

        String token = Jwts.builder()
            .claim("type", "refresh")
            .claim("socialId", member.getSocialId())  // ★ refresh token에서 socialId 추출 가능하도록 추가
            .issuer(ISSUER)
            .audience().add(member.getEmail()).and()
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact();

        log.debug("[JWT] RefreshToken generated for: {}", member.getEmail());
        return RefreshToken.of(token);
    }


    @Override
    public String getSocialIdFromRefreshToken(String refreshToken) {
        Claims claims = parseClaims(refreshToken);
        return claims.get("socialId", String.class);
    }


    public Claims parseClaims(String token) {
        try {
            return jwtParser.parseSignedClaims(token).getPayload();
        } catch (ExpiredJwtException e) {
            return e.getClaims(); // 만료여도 claims 읽기 허용
        } catch (JwtException e) {
            log.warn("[JWT] Invalid token: {}", e.getMessage());
            throw new BaseException(ErrorCode.INVALID_TOKEN);
        }
    }


    @Override
    public void validateTokenOrThrow(String token) {
        try {
            jwtParser.parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            throw new BaseException(ErrorCode.EXPIRED_ACCESS_TOKEN);
        } catch (JwtException | IllegalArgumentException e) {
            throw new BaseException(ErrorCode.INVALID_TOKEN);
        }
    }


    @Override
    public Authentication getAuthentication(String token) {
        String email = parseAudience(token);
        UserDetails userDetails = memberDetailsService.loadUserByUsername(email);

        return new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
    }


    public String parseAudience(String token) {
        try {
            Jws<Claims> claims = jwtParser.parseSignedClaims(token);
            Date expiration = claims.getPayload().getExpiration();

            if (expiration.before(new Date())) {
                throw new BaseException(ErrorCode.EXPIRED_ACCESS_TOKEN);
            }

            return claims.getPayload().getAudience().iterator().next();
        } catch (JwtException e) {
            log.warn("[JWT] Invalid token: {}", e.getMessage());
            throw new BaseException(ErrorCode.INVALID_TOKEN);
        }
    }


    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JWT_ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    log.debug("[JWT] AccessToken found in cookie");
                    return cookie.getValue();
                }
            }
        }

        String bearer = request.getHeader(JWT_ACCESS_TOKEN_HEADER_NAME);
        if (StringUtils.hasText(bearer) && bearer.startsWith(JWT_ACCESS_TOKEN_TYPE)) {
            log.debug("[JWT] AccessToken found in header");
            return bearer.substring(7);
        }

        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JWT_REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    log.debug("[JWT] RefreshToken found in cookie");
                    return cookie.getValue();
                }
            }
        }

        String bearer = request.getHeader(JWT_REFRESH_TOKEN_COOKIE_NAME);
        if (StringUtils.hasText(bearer) && bearer.startsWith(JWT_ACCESS_TOKEN_TYPE)) {
            log.debug("[JWT] RefreshToken found in header");
            return bearer.substring(7);
        }

        return null;
    }
}
