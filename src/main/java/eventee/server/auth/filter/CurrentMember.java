package eventee.server.auth.filter;

import io.swagger.v3.oas.annotations.Parameter;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

/**
 * 현재 인증된 Member 엔티티를 파라미터로 바로 주입받기 위한 어노테이션입니다.
 * SecurityContext에 저장된 MemberDetails에서 Member 객체를 자동 추출합니다.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal(expression = "member")
@Parameter(hidden = true)
public @interface CurrentMember {
}
