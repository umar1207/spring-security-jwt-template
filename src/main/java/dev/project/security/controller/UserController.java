package dev.project.security.controller;

import dev.project.security.entity.AuthRequest;
import dev.project.security.entity.UserInfo;
import dev.project.security.service.JwtService;
import dev.project.security.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    private UserInfoService service;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public ResponseEntity<?> welcome(){
        return ResponseEntity.ok("Unsecured endpoint");
    }

    @PostMapping("/addNewUser")
    public ResponseEntity<?> addNewUser(@RequestBody UserInfo userInfo){
        return ResponseEntity.ok(service.addUser(userInfo));
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<?> userProfile(){
        return ResponseEntity.ok("Welcome to user profile");
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> adminProfile(){
        return ResponseEntity.ok("Welcome to admin profile");
    }
    @PostMapping("/generateToken")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest){
        Authentication authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
        if(authentication.isAuthenticated()){
            return jwtService.generateToken(authRequest.getUsername());
        }else{
            throw new UsernameNotFoundException("invalid Request");
        }
    }
}
