package com.example.jwtdemo.model;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * User entity that also implements Spring Security's UserDetails.
 * This means the object coming back from the DB is directly usable
 * by Spring Security — no extra adapter class needed.
 */
@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role; // e.g. "ROLE_USER", "ROLE_ADMIN"

    // ── Constructors ────────────────────────────────────────────────────────────

    public User() {}

    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    // ── UserDetails contract ─────────────────────────────────────────────────────

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override public String getPassword()  { return password; }
    @Override public String getUsername()  { return username; }

    // For this demo all accounts are always active/non-expired/non-locked
    @Override public boolean isAccountNonExpired()    { return true; }
    @Override public boolean isAccountNonLocked()     { return true; }
    @Override public boolean isCredentialsNonExpired(){ return true; }
    @Override public boolean isEnabled()              { return true; }

    // ── Getters / Setters ────────────────────────────────────────────────────────

    public Long   getId()       { return id; }
    public String getRole()     { return role; }

    public void setId(Long id)           { this.id = id; }
    public void setUsername(String u)    { this.username = u; }
    public void setPassword(String p)    { this.password = p; }
    public void setRole(String r)        { this.role = r; }
}
