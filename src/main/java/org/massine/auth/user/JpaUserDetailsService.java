package org.massine.auth.user;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Service
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {
    private final JdbcTemplate jdbc;
    private final PasswordEncoder pe;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = jdbc.queryForObject("""
  SELECT id, username, password_hash, enabled
  FROM auth_schema.users
  WHERE email = ? OR username = ?
  """, (rs, i) -> map(rs), username, username);


        var roles = jdbc.query("""
      SELECT r.name FROM auth_schema.roles r
      JOIN auth_schema.user_roles ur ON ur.role_id=r.id
      WHERE ur.user_id=?
      """, (rs, i) -> rs.getString(1), user.id());
        return User.withUsername(user.username())
                .password(user.passwordHash())
                .authorities(roles.stream().map(SimpleGrantedAuthority::new).toList())
                .accountLocked(!user.enabled())
                .build();
    }

    record U(Long id, String username, String passwordHash, boolean enabled) {}
    private U map(ResultSet rs) throws SQLException {
        return new U(rs.getLong("id"), rs.getString("username"),
                rs.getString("password_hash"), rs.getBoolean("enabled"));
    }
}
