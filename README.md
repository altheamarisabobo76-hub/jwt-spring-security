# JWT Demo — Spring Boot 3 + MySQL

## Project Structure

```
src/main/java/com/example/jwtdemo/
├── JwtDemoApplication.java          ← Entry point
├── config/
│   └── SecurityConfig.java          ← Filter chain, CSRF, session policy, auth provider
├── controller/
│   └── AuthController.java          ← /api/auth/login, demo endpoints, test-user seeder
├── filter/
│   └── JwtAuthenticationFilter.java ← Reads Bearer token, validates it, sets SecurityContext
├── model/
│   ├── User.java                    ← JPA entity + UserDetails implementation
│   └── UserRepository.java          ← Spring Data repo
└── service/
    ├── CustomUserDetailsService.java ← Loads user from DB for Spring Security
    └── JwtUtil.java                  ← Token generation, extraction, validation
```

## Setup

### 1. Configure MySQL

Open `src/main/resources/application.yml` and update:

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/jwt_demo_db?createDatabaseIfNotExist=true&...
    username: root          # your MySQL username
    password: yourpassword  # your MySQL password
```

The database `jwt_demo_db` is created automatically on first run.

### 2. Run

```bash
./mvnw spring-boot:run
# or in IntelliJ: Run → JwtDemoApplication
```

On startup you will see:
```
==============================================
 Test user seeded:
   username : admin
   password : password123
==============================================
```

## Testing with curl

### Login → get a token
```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}'

# Response: {"token":"eyJhbGciOiJIUzI1NiJ9..."}
```

### Hit the public endpoint (no token needed)
```bash
curl http://localhost:8080/api/public/hello
# Response: {"message":"Hello from a PUBLIC endpoint!"}
```

### Hit the protected endpoint (token required)
```bash
TOKEN="paste_your_token_here"
curl http://localhost:8080/api/secure/hello \
  -H "Authorization: Bearer $TOKEN"
# Response: {"message":"Hello, admin! You reached a PROTECTED endpoint."}
```

### Hit protected without token → 401
```bash
curl -i http://localhost:8080/api/secure/hello
# HTTP/1.1 401  {"error":"Unauthorized","message":"..."}
```

## Key Design Decisions

| Choice | Reason |
|---|---|
| `User implements UserDetails` | No wrapper/adapter class needed; the entity is directly usable by Spring Security |
| `SessionCreationPolicy.STATELESS` | No server-side session; every request must carry its own JWT |
| Filter before `UsernamePasswordAuthenticationFilter` | Ensures JWT auth runs first on every request |
| BCryptPasswordEncoder | Industry-standard adaptive hashing; never store plain text |
| `jjwt 0.11.5` | Stable, well-maintained JJWT version compatible with Spring Boot 3 |
| `CommandLineRunner` seeder | Creates a test user on first startup; remove in production |

## Common Errors & Fixes

| Error | Fix |
|---|---|
| `Access denied for user 'root'@'localhost'` | Wrong MySQL credentials in `application.yml` |
| `Communications link failure` | MySQL is not running, or wrong port |
| `IllegalStateException: jwt.secret must decode to at least 32 bytes` | The secret in `application.yml` is too short; use the provided default or generate a new one |
| `401 Unauthorized` on protected route | Missing or expired token; re-login and use the new token |
