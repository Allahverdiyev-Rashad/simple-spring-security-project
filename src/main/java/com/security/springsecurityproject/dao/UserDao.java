package com.security.springsecurityproject.dao;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Collections;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class UserDao {

    private static final String PASS = "password";
    private final List<UserDetails> APP_USERS = List.of(
            new User("resad@gmail.com",
                    PASS,
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))),
            new User(PASS,
                    "password",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")))
    );

    public UserDetails findUserByEmail(String email) {
        return APP_USERS.stream()
                .filter(u -> u.getUsername().equals(email))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

}
