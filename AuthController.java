package com.example.jwtdemo.controller;

import com.example.jwtdemo.model.User;
import com.example.jwtdemo.model.UserRepository;
import com.example.jwtdemo.service.JwtUtil;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Handles authentication requests.
 *
 * POST /api/auth/login   → validates credentials and returns a JWT
 * GET  /api/public/hello → a public endpoint (no token required)
 * GET  /api/secure/hello → a protected endpoint (token required)
 */
@RestController
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthenticationManager authManager,
                          JwtUtil jwtUtil,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.authManager    = authManager;
        this.jwtUtil        = jwtUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ── Login endpoint ───────────────────────────────────────────────────────────

    /**
     * Accepts { "username": "...", "password": "..." }
     * Returns { "token": "eyJ..." } on success, or 401 on failure.
     */
    @PostMapping("/api/auth/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {

        String username = body.get("username");
        String password = body.get("password");

        // Delegate credential verification to Spring Security's AuthenticationManager.
        // Throws AuthenticationException (→ 401) if credentials are wrong.
        Authentication authentication = authManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );

        // Cast the principal back to UserDetails so JwtUtil can read the username
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(Map.of("token", token));
    }

    // ── Demo endpoints ───────────────────────────────────────────────────────────

    /** Publicly accessible — no JWT needed. */
    @GetMapping("/api/public/hello")
    public ResponseEntity<Map<String, String>> publicHello() {
        return ResponseEntity.ok(Map.of("message", "Hello from a PUBLIC endpoint!"));
    }

    /** Requires a valid Bearer token in the Authorization header. */
    @GetMapping("/api/secure/hello")
    public ResponseEntity<Map<String, String>> secureHello(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Hello, " + auth.getName() + "! You reached a PROTECTED endpoint."
        ));
    }

    // ── Test-user seeder ─────────────────────────────────────────────────────────

    /**
     * Creates a test user on startup if one does not already exist.
     * Credentials: username=admin  password=password123
     *
     * Remove or gate this behind a profile in production!
     */
    @Bean
    public CommandLineRunner seedTestUser() {
        return args -> {
            if (userRepository.findByUsername("admin").isEmpty()) {
                User testUser = new User(
                    "admin",
                    passwordEncoder.encode("password123"),
                    "ROLE_ADMIN"
                );
                userRepository.save(testUser);
                System.out.println("==============================================");
                System.out.println(" Test user seeded:");
                System.out.println("   username : admin");
                System.out.println("   password : password123");
                System.out.println("==============================================");
            }
        };
    }
}
