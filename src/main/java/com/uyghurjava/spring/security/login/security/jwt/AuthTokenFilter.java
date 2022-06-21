package com.uyghurjava.spring.security.login.security.jwt;

import com.uyghurjava.spring.security.login.security.services.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Let’s define a filter that executes once per request.
 * So we create AuthTokenFilter class that extends OncePerRequestFilter and override doFilterInternal() method.
 *
 * What we do inside doFilterInternal():
 * – get JWT from the HTTP Cookies
 * – if the request has JWT, validate it, parse username from it
 * – from username, get UserDetails to create an Authentication object
 * – set the current UserDetails in SecurityContext using setAuthentication(authentication) method.
 *
 * After this, everytime you want to get UserDetails, just use SecurityContext like this:
 * UserDetails userDetails =
 * 	(UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
 * // userDetails.getUsername()
 * // userDetails.getPassword()
 * // userDetails.getAuthorities()
 */

public class AuthTokenFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    /**
     *
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            //get JWT from the HTTP Cookies
            String jwt = parseJwt(request);
            //if the request has JWT, validate it, parse username from it
            if(jwt != null && jwtUtils.validateJwtToken(jwt)){

                //from username, get UserDetails to create an Authentication object
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails =userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //set the current UserDetails in SecurityContext using setAuthentication(authentication) method.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        }catch (Exception e){
            logger.error("Cannot set user authentication: {}", e);
        }
        logger.info("AuthTokenFilter class does his job, userSign-Up == userSign-In");
        filterChain.doFilter(request, response);

    }
    private String parseJwt(HttpServletRequest request){
        //get JWT from the HTTP Cookies
        String jwt = jwtUtils.getJwtFromCookies(request);
        return jwt;
    }
}
