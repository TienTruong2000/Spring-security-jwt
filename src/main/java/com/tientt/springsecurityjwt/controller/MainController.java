package com.tientt.springsecurityjwt.controller;

import com.tientt.springsecurityjwt.models.request.AuthenticateRequest;
import com.tientt.springsecurityjwt.models.response.AuthenticateResponse;
import com.tientt.springsecurityjwt.service.CustomUserDetailsService;
import com.tientt.springsecurityjwt.utils.JwtUtil;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping("/hello")
    String hello() {
        return "Hello world";
    }

    @PostMapping("/authenticate")
    ResponseEntity<AuthenticateResponse> authentication(@RequestBody AuthenticateRequest authenticateRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticateRequest.getUsername(),
                            authenticateRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("incorrect username or password", e);
        }
        UserDetails userDetails = userDetailsService.
                loadUserByUsername(authenticateRequest.getUsername());

        String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok((new AuthenticateResponse(jwt)));
    }
}
