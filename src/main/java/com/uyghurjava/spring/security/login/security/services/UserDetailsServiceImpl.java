package com.uyghurjava.spring.security.login.security.services;

import com.uyghurjava.spring.security.login.models.User;
import com.uyghurjava.spring.security.login.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: "+username));
        logger.info("User details successfully loaded from userRepository by loadUserByUsername in UserDetailsImpl");
        //we get full custom User object using UserRepository, then we build a UserDetails object using static build() method.
        return UserDetailsImpl.build(user);
    }
}
