package com.klu.controller;

import com.klu.dto.AuthRequest;
import com.klu.dto.AuthResponse;
import com.klu.dto.OtpRequest;
import com.klu.dto.UserDTO;
import com.klu.entity.Role;
import com.klu.entity.User;
import com.klu.security.JwtUtil;
import com.klu.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    @PostMapping("/send-otp")
    public String sendOtp(@RequestBody OtpRequest req) {
        return userService.sendOtp(req.getEmail());
    }

    @PostMapping("/resend-otp")
    public String resendOtp(@RequestBody OtpRequest req) {
        return userService.resendOtp(req.getEmail());
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestBody OtpRequest req) {
        return userService.verifyOtp(req.getEmail(), req.getOtp());
    }

    @PostMapping("/register")
    public String register(@RequestBody UserDTO dto) {
        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPassword(dto.getPassword());
        user.setRole(Role.valueOf(dto.getRole().toUpperCase()));

        userService.register(user);
        return "Account created successfully";
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest req) {
        User user = userService.authenticate(req);

        String token = jwtUtil.generateToken(
                user.getEmail(),
                user.getRole().name()
        );

        AuthResponse res = new AuthResponse();
        res.setToken(token);
        return res;
    }
}