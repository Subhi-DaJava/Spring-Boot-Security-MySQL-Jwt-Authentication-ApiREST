package com.uyghurjava.spring.security.login.controller;

import com.uyghurjava.spring.security.login.models.User;
import com.uyghurjava.spring.security.login.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

/**
 * Controller for testing Authorization
 *
 * There are 4 APIs:
 * – /api/test/all for public access
 * – /api/test/user for users has ROLE_USER or ROLE_MODERATOR or ROLE_ADMIN
 * – /api/test/mod for users has ROLE_MODERATOR
 * – /api/test/admin for users has ROLE_ADMIN
 *
 *  @EnableGlobalMethodSecurity(prePostEnabled = true) for WebSecurityConfig class
 *
 * @Configuration
 * @EnableWebSecurity
 * @EnableGlobalMethodSecurity(prePostEnabled = true)
 *
 * public class WebSecurityConfig extends WebSecurityConfigurerAdapter { ... }
 * Secure methods in our Apis with @PreAuthorize annotation easily.
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    private final UserRepository userRepository;

    public TestController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/all")
    public String allAccess(){
        return "You have the right for the Public Content.";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess(){
        logger.info("Hi, User ! (TestController)");
        return "You have the right for the User Content, welcome!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess(){
        logger.info("Hi, Admin ! (TestController)");
        return "Hi, Admin !, welcome to Admin Dashboard.";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(){
        logger.info("Hi, Moderator ! (TestController)");
        return "Hi, Moderator !, welcome to our Moderator Dashboard.";
    }

    @GetMapping("/admin/allUsers")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> showAllUsers(){
        List<User> users = userRepository.findAll();
        logger.info("All users are here(TestController).");
        return ResponseEntity.ok().body(users);
    }

    @GetMapping("user/profil")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_USER') or hasAuthority('ROLE_MODERATOR')")
    public User profile(Principal principal){
        return userRepository.findByUsername(principal.getName())
                .orElseThrow( () -> new RuntimeException("This user with username=" + principal.getName() + "doesn't exist!!"));
    }

}
