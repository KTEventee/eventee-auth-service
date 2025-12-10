package eventee.server.auth.token;

public class JwtProperties {
    public static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30; // 30분
    public static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7; // 1주일
    public static final long LOGIN_EXPIRE_TIME = 1000 * 60 * 60*2; // 2시간
    public static final String JWT_ACCESS_TOKEN_HEADER_NAME = "Authorization";
    public static final String JWT_ACCESS_TOKEN_TYPE = "Bearer ";
    public static final String JWT_REFRESH_TOKEN_COOKIE_NAME = "X-REFRESH-TOKEN";
    public static final String JWT_ACCESS_TOKEN_COOKIE_NAME = "ACCESS_TOKEN";
}