package org.wa.auth.lib.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;
import org.wa.auth.lib.service.AdminService;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private final JwtService jwtService;

    private final AdminService adminService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletResponse httpResponse = (HttpServletResponse) response;
        final String token = getTokenFromRequest((HttpServletRequest) request);
        if (token != null && jwtService.validateAccessToken(token)) {
            final Claims claims = jwtService.getAccessClaims(token);
            UUID externalId = UUID.fromString(claims.getSubject());
            if (adminService.isUserBlocked(externalId)) {
                log.warn("User {} is blocked", externalId);
                String message = "user " + externalId + " is blocked";
                httpResponse.setStatus(HttpStatus.FORBIDDEN.value());
                httpResponse.setContentType(MediaType.TEXT_PLAIN_VALUE);
                httpResponse.setCharacterEncoding("UTF-8");
                httpResponse.getWriter().write(message);
                httpResponse.getWriter().flush();
                return;
            }
            final JwtAuthentication jwtAuth = JwtUtils.createJwtAuth(claims);
            jwtAuth.setAuthenticated(true);
            SecurityContextHolder.getContext().setAuthentication(jwtAuth);
        }
        chain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String jwtHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (jwtHeader != null && jwtHeader.startsWith("Bearer ")) {
            return jwtHeader.substring(7);
        }
        return null;
    }
}