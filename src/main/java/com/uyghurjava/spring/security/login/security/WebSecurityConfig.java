package com.uyghurjava.spring.security.login.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * – @EnableWebSecurity allows Spring to find and automatically apply the class to the global Web Security.
 * – @EnableGlobalMethodSecurity provides AOP security on methods. It enables @PreAuthorize, @PostAuthorize,
 * it also supports JSR-250. You can find more parameters in configuration in Method Security Expressions.
 *
 * – We override the configure(HttpSecurity http) method from WebSecurityConfigurerAdapter interface.
 * It tells Spring Security how we configure CORS and CSRF, when we want to require all users to be authenticated or not,
 * which filter (AuthTokenFilter) and when we want it to work (filter before UsernamePasswordAuthenticationFilter),
 * which Exception Handler is chosen (AuthEntryPointJwt).
 *
 * – Spring Security will load User details to perform authentication & authorization.
 * So it has UserDetailsService interface that we need to implement.
 *
 * The implementation of UserDetailsService will be used for configuring DaoAuthenticationProvider
 * by AuthenticationManagerBuilder.userDetailsService() method.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        //securedEnabled = true
        //jsr250Enabled = true
        prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    /**
     * Spring Security will load User details to perform authentication & authorization.
     * So it has UserDetailsService interface that we need to implement.
     */
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }

    /**
     * The implementation of UserDetailsService will be used for configuring DaoAuthenticationProvider
     * by AuthenticationManagerBuilder.userDetailsService() method.
     * @return
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * PasswordEncoder for the DaoAuthenticationProvider. If we don’t specify, it will use plain text.
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * This overriding that tells Spring Security how we configure CORS and CSRF, when we want to require all users to be authenticated or not,
     * which filter (AuthTokenFilter) and when we want it to work (filter before UsernamePasswordAuthenticationFilter),
     *  which Exception Handler is chosen (AuthEntryPointJwt).
     * @param http
     * @throws Exception
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests().antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/test/**").permitAll()
                .anyRequest().authenticated();
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
