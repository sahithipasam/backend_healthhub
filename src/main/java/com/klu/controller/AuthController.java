package com.klu.controller;

import com.klu.dto.AuthRequest;
import com.klu.dto.AuthResponse;
import com.klu.dto.UserDTO;
import com.klu.entity.User;
import com.klu.security.JwtUtil;
import com.klu.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final ModelMapper mapper;

    // 🔹 Register (DTO response)
    @PostMapping("/register")
    public UserDTO register(@RequestBody User user) {

        User saved = userService.register(user);

        return mapper.map(saved, UserDTO.class);
    }

    // 🔹 Login (JWT with role)
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