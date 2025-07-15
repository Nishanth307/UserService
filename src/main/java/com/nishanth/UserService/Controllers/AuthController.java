package com.nishanth.UserService.Controllers;

import com.nishanth.UserService.dtos.*;
import com.nishanth.UserService.models.SessionStatus;
import com.nishanth.UserService.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;
    public AuthController(AuthService authService){
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDto> signUp(@RequestBody SignUpRequestDto request) {
        UserDto dto = authService.signUp(request.getEmail(), request.getPassword());
        return new ResponseEntity<>(dto, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto request) {
        return authService.login(request.getEmail(), request.getPassword());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDto request) {
        return authService.logout(request.getToken(),request.getUserId());
    }

//    public ResponseEntity<SessionStatus> validateToken(ValidateTokenRequestDto request) {
    @PostMapping("/validate/{userId}")
    public ResponseEntity<SessionStatus> validateToken(@PathVariable String userId,@RequestHeader String token){
        SessionStatus sessionStatus = authService.validate(token, Long.valueOf(userId));
        return new ResponseEntity<>(sessionStatus, HttpStatus.OK);
    }

}
