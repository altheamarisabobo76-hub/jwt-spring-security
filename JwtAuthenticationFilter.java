package com.example.jwtdemo.filter;

import com.example.jwtdemo.service.CustomUserDetailsService;
import com.example.jwtdemo.service.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Intercepts every request exactly once.
 * If a valid Bearer token is present the user is authenticated in the
 * SecurityContext so that downstream filters / controllers can trust the
 * principal without touching a session store.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil,
                                   CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Pull the Authorization header
        final String authHeader = request.getHeader("Authorization");

        // If missing or not a Bearer token, skip straight to the next filter
        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Strip the "Bearer " prefix (7 characters)
        final String jwt = authHeader.substring(7);

        try {
            // 3. Extract username from the token
            final String username = jwtUtil.extractUsername(jwt);

            // 4. Only authenticate if not already authenticated in this request
            if (StringUtils.hasText(username) &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 5. Validate signature + expiry
                if (jwtUtil.isTokenValid(jwt, userDetails)) {

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,                          // credentials (not needed post-auth)
                                    userDetails.getAuthorities()
                            );

                    authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                    // 6. Publish authentication to the SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

        } catch (Exception ex) {
            // Log and continue — Spring Security will return 401 for unauthenticated requests
            log.warn("JWT authentication failed for request [{}]: {}",
                     request.getRequestURI(), ex.getMessage());
        }

        // 7. Always continue the filter chain
        filterChain.doFilter(request, response);
    }
}
