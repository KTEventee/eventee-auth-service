package eventee.server.auth.exception.status;


import eventee.server.common.exception.codes.BaseCode;
import eventee.server.common.exception.codes.reason.Reason;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum AuthErrorStatus implements BaseCode {

  // 로그아웃 관련
  AUTH_LOGOUT_REFRESH_TOKEN_MISSING(HttpStatus.BAD_REQUEST, "AUTH-0200", "쿠키에 Refresh Token이 존재하지 않습니다."),
  AUTH_LOGOUT_TOKEN_NOT_FOUND_IN_REDIS(HttpStatus.BAD_REQUEST, "AUTH-0201", "Redis에 저장된 Refresh Token이 존재하지 않습니다."),
  AUTH_LOGOUT_TOKEN_MISMATCH(HttpStatus.UNAUTHORIZED, "AUTH-0202", "요청한 Refresh Token이 서버에 저장된 값과 일치하지 않습니다."),
  AUTH_LOGOUT_REDIS_DELETE_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-0203", "Redis에서 Refresh Token 삭제 중 오류가 발생했습니다."),
  AUTH_LOGOUT_UNKNOWN_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-0204", "로그아웃 처리 중 알 수 없는 오류가 발생했습니다."),
  AUTH_IMAGE_PRESIGNED_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "AUTH-0105", "Presigned URL 생성 중 오류가 발생했습니다."),
  AUTH_IMAGE_INVALID_REQUEST(HttpStatus.BAD_REQUEST, "AUTH-0106", "이미지 업로드 요청 데이터가 유효하지 않습니다.");



  private final HttpStatus httpStatus;
  private final String code;
  private final String message;

  @Override
  public Reason.ReasonDto getReasonHttpStatus() {
    return Reason.ReasonDto.builder()
        .message(message)
        .code(code)
        .isSuccess(false)
        .httpStatus(httpStatus)
        .build();
  }
}
