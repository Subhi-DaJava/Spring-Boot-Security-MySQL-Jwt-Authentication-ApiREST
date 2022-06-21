package com.uyghurjava.spring.security.login.controller;

import com.uyghurjava.spring.security.login.models.ERole;
import com.uyghurjava.spring.security.login.models.Role;
import com.uyghurjava.spring.security.login.models.User;
import com.uyghurjava.spring.security.login.payload.request.LoginRequest;
import com.uyghurjava.spring.security.login.payload.request.SignupRequest;
import com.uyghurjava.spring.security.login.payload.response.MessageResponse;
import com.uyghurjava.spring.security.login.payload.response.UserInfoResponse;
import com.uyghurjava.spring.security.login.repository.RoleRepository;
import com.uyghurjava.spring.security.login.repository.UserRepository;
import com.uyghurjava.spring.security.login.security.jwt.JwtUtils;
import com.uyghurjava.spring.security.login.security.services.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Controller for Authentication
 *
 * This controller provides APIs for register and login, logout actions.
 *
 * – /api/auth/signup
 *
 * check existing username/email
 * create new User (with ROLE_USER if not specifying role)
 * save User to database using UserRepository
 *
 * – /api/auth/signin
 *
 * authenticate { username, password }
 * update SecurityContext using Authentication object
 * generate JWT
 * get UserDetails from Authentication object
 * response contains JWT and UserDetails data
 *
 * – /api/auth/signout: clear the Cookie.
 */

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Value(("uyghurcoder.app.jwtCookieName"))
    private String jwtCookie;

    final
    AuthenticationManager authenticationManager;
    final
    UserRepository userRepository;
    final
    RoleRepository roleRepository;
    final
    PasswordEncoder encoder;
    final
    JwtUtils jwtUtils;

    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
        logger.debug("This method authenticateUser(AuthController) starts here");
        // authenticate { username, password }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        // update SecurityContext using Authentication object
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //  get UserDetails from Authentication object
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        //  generate JWT
        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        logger.info("AuthenticateUser(AuthController) is successful!");
        //response contains JWT and UserDetails data
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(new UserInfoResponse(userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles));

    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){
        logger.debug("This registerUser(AuthController) starts here");
        if (userRepository.existsByUsername(signupRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }
        if(userRepository.existsByEmail(signupRequest.getEmail())){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }
        //Create new user's account with ROLE_USER if not specifying role --> null or empty
        User user = new User(
                signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();

        Set<Role> roles = new HashSet<>();

        if(strRoles == null || strRoles.isEmpty()){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role){
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(modRole);
                        break;
                    default: // unknown roleName
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
        logger.info("This user is successfully registered(AuthController) with registerUser method");
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(){
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        logger.info("This user is successfully sign-out(AuthController) with log-out method");
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("You have been signed out perfectly!"));
    }

    @PostMapping("/admin/addRole")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MEDERATOR')")
    @Transactional
    public ResponseEntity<?> addRoleToUser(@Valid @RequestParam String username, @RequestParam String roleName){

        logger.debug("This method addRoleToUser(AuthController) starts here");

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("This user with username= " + username + " doesn't exist in DB (from method addRole -> AuthController)"));


        Set<Role> userRoles = user.getRoles();

        if(userRoles.contains(roleName)){
            return ResponseEntity.ok().body(new MessageResponse("This roleName=" + roleName + " is already added to this user with username=" + username));
        }
        //TODO: Create a check if roleName equals any String sauf 'mod','admin' or 'user'
        if(roleName == null || roleName.isEmpty()){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
            userRoles.add(userRole);
        } else {
            switch (roleName) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        userRoles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        userRoles.add(modRole);
                        break;
                    default: // unknown roleName
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        userRoles.add(userRole);
                }

        }

        user.setRoles(userRoles);
        userRepository.save(user);

        logger.info("AuthenticateUser(AuthController) is successful!");

        return ResponseEntity.ok().body(new MessageResponse("This roleName={" + roleName + "} is successfully added to this user with username={" + username + "}"));
    }

    //TODO: method for Refresh Token
    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response){

        String authToken = request.getHeader(jwtCookie);
        if(authToken != null && authToken.startsWith("Bearer")){
            String refreshToken = authToken.substring(7);
            // verify the signature
        }
    }
}
