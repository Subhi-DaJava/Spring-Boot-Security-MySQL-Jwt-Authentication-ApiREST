package com.uyghurjava.spring.security.login.payload.request;

import javax.validation.constraints.NotBlank;

/**
 * Let me summarize the payloads (POJOs) for our RestAPIs:
 * – Requests:
 *
 * LoginRequest: { username, password }
 * SignupRequest: { username, email, password }
 * – Responses:
 *
 * UserInfoResponse: { id, username, email, roles }
 * MessageResponse: { message }
 */

public class LoginRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
