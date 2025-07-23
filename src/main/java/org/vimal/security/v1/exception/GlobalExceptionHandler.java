package org.vimal.security.v1.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.vimal.security.v1.util.logging.ToJsonForLoggingUtil;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> handleAuthenticationException(AuthenticationException ex) {
        return ResponseEntity.status(401).body(
                Map.of(
                        "error", "Unauthorized",
                        "message", ex.getMessage()
                )
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException ex) {
        return ResponseEntity.status(403).body(
                Map.of(
                        "error", "Forbidden",
                        "message", ex.getMessage()
                )
        );
    }

    @ExceptionHandler({BadRequestExc.class, HttpMessageNotReadableException.class})
    public ResponseEntity<?> handleBadRequestExceptions(Exception ex) {
        return ResponseEntity.badRequest().body(
                Map.of(
                        "error", "Bad Request",
                        "message", ex.getMessage()
                )
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGenericException(Exception ex) {
        Map<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("severity", "Error");
        errorResponse.put("message", ex.getMessage());
        Map<String, Object> innerErrorData = new LinkedHashMap<>();
        innerErrorData.put("exception", ex.toString());
        innerErrorData.put("stack", formatStackTrace(ex));
        errorResponse.put("innerErrorData", innerErrorData);
        log.error("An unexpected error occurred: {}\n{}", ex.getMessage(), ToJsonForLoggingUtil.toJson(errorResponse));
        return ResponseEntity.internalServerError().body(errorResponse);
    }

    private List<String> formatStackTrace(Throwable ex) {
        return Arrays.stream(ex.getStackTrace()).map(ste -> ste.getClassName() + "." + ste.getMethodName() + "(" + ste.getFileName() + ":" + ste.getLineNumber() + ")").toList();
    }
}