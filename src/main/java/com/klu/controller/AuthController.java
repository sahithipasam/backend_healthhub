package com.klu.controller;

import com.klu.dto.AuthRequest;
import com.klu.dto.AuthResponse;
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

    // 🔹 REGISTER
    @PostMapping("/register")
    public UserDTO register(@RequestBody UserDTO dto) {

        User user = new User();

        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPassword(dto.getPassword());

        // 🔥 CRITICAL LINE (role comes from frontend)
        user.setRole(Role.valueOf(dto.getRole()));

        User saved = userService.register(user);

        UserDTO res = new UserDTO();
        res.setName(saved.getName());
        res.setEmail(saved.getEmail());
        res.setRole(saved.getRole().name());

        return res;
    }

    // 🔹 LOGIN
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