package com.uyghurjava.spring.security.login.security.jwt;

import com.uyghurjava.spring.security.login.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

/**
 * This class has 3 main functions:
 * getJwtFromCookies: get JWT from Cookies by Cookie name
 * generateJwtCookie: generate a Cookie containing JWT from username, date, expiration, secret
 * getCleanJwtCookie: return Cookie with null value (used for clean Cookie)
 * getUserNameFromJwtToken: get username from JWT
 * validateJwtToken: validate a JWT with a secret
 */

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${uyghurcoder.app.jwtSecret}")
    private String jwtSecret;
    @Value("${uyghurcoder.app.jwtExpirationMs}")
    private int jwtExpirationMs;
    @Value(("uyghurcoder.app.jwtCookieName"))
    private String jwtCookie;

    //getJwtFromCookies: get JWT from Cookies by Cookie name
    public String getJwtFromCookies(HttpServletRequest request){
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }
    //generateJwtCookie: generate a Cookie containing JWT from username, date, expiration, secret
    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal){
        String jwt = generateTokenFromUserName(userPrincipal.getUsername());
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();
        return cookie;
    }
    //getCleanJwtCookie: return Cookie with null value (used for clean Cookie)
    public ResponseCookie getCleanJwtCookie(){
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
        return cookie;
    }

    //getUserNameFromJwtToken: get username from JWT
    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }
    //validateJwtToken: validate a JWT with a secret
    public boolean validateJwtToken(String authToken){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        }catch (SignatureException e){
            logger.error("Invalid JWT signature: {}", e.getMessage());
        }catch (MalformedJwtException e){
            logger.error("Invalid JWT token: {}", e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("JWT token is expired: {}", e.getMessage());
        }catch (UnsupportedJwtException e){
            logger.error("JWT token is unsupported:{}", e.getMessage());
        }catch (IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Remember that we’ve added uyghurcoder.app.jwtSecret, uyghurcoder.app.jwtExpirationMs and uyghurcoder.app.jwtCookieName properties
     * in application.properties file.
     * @param username
     * @return
     */
    public String generateTokenFromUserName(String username){
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    //TODO: create refresh-token and Map<String, String> idToken = new HashMap<>(); put two tokens in Map
    //IdToken.put("access-token", secret);
    //idToken.pun("refresh-token", secret)
    //response.setContentType("application/json");
    //new ObjectMapper().writeValue(response.getOutputStream, idToken);
}
