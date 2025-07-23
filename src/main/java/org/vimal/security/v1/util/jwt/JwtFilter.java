package org.vimal.security.v1.util.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.vimal.security.v1.impl.UserDetailsImpl;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws IOException {
        try {
            var authorizationHeader = request.getHeader("Authorization");
            if (shouldProcessAuthentication(authorizationHeader)) {
                processJwtAuthentication(request, authorizationHeader);
            }
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            handleAuthError(response, ex);
        }
    }

    private boolean shouldProcessAuthentication(String authorizationHeader) {
        return authorizationHeader != null && authorizationHeader.startsWith("Bearer ") && SecurityContextHolder.getContext().getAuthentication() == null;
    }

    private void processJwtAuthentication(HttpServletRequest request,
                                          String authorizationHeader) throws JoseException {
        var jwtToken = authorizationHeader.substring(7);
        var userDetails = jwtUtil.verifyAccessToken(jwtToken);
        setSecurityContextAuthentication(request, userDetails);
    }

    private void setSecurityContextAuthentication(HttpServletRequest request,
                                                  UserDetailsImpl userDetails) {
        var authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void handleAuthError(HttpServletResponse response,
                                 Exception ex) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        var error = Map.of(
                "error", "Unauthorized",
                "message", ex.getMessage()
        );
        objectMapper.writeValue(response.getWriter(), error);
    }
}