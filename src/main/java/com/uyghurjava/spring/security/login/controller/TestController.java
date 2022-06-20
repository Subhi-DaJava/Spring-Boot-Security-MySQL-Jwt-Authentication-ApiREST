package com.uyghurjava.spring.security.login.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @GetMapping("/all")
    public String allAccess(){
        return "You have the right fot the Public Content";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess(){
        logger.info("Hi, User ! (TestController)");
        return "You have the right for the User Content, welcome!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('Admin')")
    public String adminAccess(){
        logger.info("Hi, Admin ! (TestController)");
        return "Hi, Admin !, welcome to Admin Dashboard";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(){
        logger.info("Hi, Moderator ! (TestController)");
        return "Hi, Moderator !, welcome to our Moderator Dashboard";
    }

}
