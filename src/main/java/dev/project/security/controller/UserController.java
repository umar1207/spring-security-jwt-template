package dev.project.security.controller;

import dev.project.security.dto.LoginRequestDto;
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

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserInfo userInfo){
        return ResponseEntity.ok(service.register(userInfo));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto loginRequestDto){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword())
        );
        if(authentication.isAuthenticated()){
            return ResponseEntity.ok(jwtService.generateToken(loginRequestDto.getUsername()));
        }else{
            throw new UsernameNotFoundException("invalid Request");
        }
    }

    @GetMapping("/user/user-endpoint")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<?> userProfile(){
        return ResponseEntity.ok("Example of User API");
    }

    @GetMapping("/admin/admin-endpoint")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> adminProfile(){
        return ResponseEntity.ok("Example of Admin API");
    }

}
