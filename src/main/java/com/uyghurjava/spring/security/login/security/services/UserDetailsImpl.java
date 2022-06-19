package com.uyghurjava.spring.security.login.security.services;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.uyghurjava.spring.security.login.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * If the authentication process is successful, we can get User’s information such as username, password, authorities from an Authentication object.
 * Authentication authentication =
 *         authenticationManager.authenticate(
 *             new UsernamePasswordAuthenticationToken(username, password)
 *         );
 * UserDetails userDetails = (UserDetails) authentication.getPrincipal();
 * // userDetails.getUsername()
 * // userDetails.getPassword()
 * // userDetails.getAuthorities()
 *
 * f we want to get more data (id, email…), we can create an implementation of this UserDetails interface. Like this class
 *
 * Look at the code below, you can notice that we convert Set<Role> into List<GrantedAuthority>.
 * It is important to work with Spring Security and Authentication object later.
 *
 * We need UserDetailsService for getting UserDetails object. You can look at UserDetailsService interface that has only one method:
 * public interface UserDetailsService {
 *   UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;}
 */


public class UserDetailsImpl implements UserDetails {
    private static final Logger logger = LoggerFactory.getLogger(UserDetailsImpl.class);

    private static final long serialVersionUID=1L;

    private Long id;
    private String username;
    private String email;
    @JsonIgnore
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String username, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user){
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        logger.info("This userDetailsImpl object from build(User user) from UserdetailsImpl");
        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities);

    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserDetailsImpl that = (UserDetailsImpl) o;
        return Objects.equals(id, that.id);
    }

}
