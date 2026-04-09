package com.klu.service;

import com.klu.dto.AuthRequest;
import com.klu.entity.User;
import com.klu.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String mailFrom;

    private final Map<String, String> otpStore = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> otpExpiryStore = new ConcurrentHashMap<>();
    private final Set<String> verifiedEmails = ConcurrentHashMap.newKeySet();

    public String sendOtp(String email) {
        String normalizedEmail = normalizeEmail(email);

        userRepository.findByEmail(normalizedEmail).ifPresent(existing -> {
            if (existing.isEnabled()) {
                throw new RuntimeException("Email already registered");
            }
        });

        String otp = generateOtp();
        otpStore.put(normalizedEmail, otp);
        otpExpiryStore.put(normalizedEmail, LocalDateTime.now().plusMinutes(5));

        sendOtpEmail(normalizedEmail, otp);
        return "OTP sent to your email";
    }

    public String resendOtp(String email) {
        return sendOtp(email);
    }

    public String verifyOtp(String email, String otp) {
        String normalizedEmail = normalizeEmail(email);
        String savedOtp = otpStore.get(normalizedEmail);
        LocalDateTime expiry = otpExpiryStore.get(normalizedEmail);

        if (savedOtp == null || expiry == null) {
            throw new RuntimeException("Please request OTP first");
        }

        if (expiry.isBefore(LocalDateTime.now())) {
            otpStore.remove(normalizedEmail);
            otpExpiryStore.remove(normalizedEmail);
            throw new RuntimeException("OTP expired");
        }

        if (!savedOtp.equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }

        verifiedEmails.add(normalizedEmail);
        otpStore.remove(normalizedEmail);
        otpExpiryStore.remove(normalizedEmail);

        return "OTP verified successfully";
    }

    public User register(User user) {
        String normalizedEmail = normalizeEmail(user.getEmail());

        if (!verifiedEmails.contains(normalizedEmail)) {
            throw new RuntimeException("Please verify OTP before registration");
        }

        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        user.setEmail(normalizedEmail);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setEnabled(true);
        user.setOtp(null);
        user.setOtpExpiry(null);

        User saved = userRepository.save(user);
        verifiedEmails.remove(normalizedEmail);

        return saved;
    }

    public User authenticate(AuthRequest request) {
        String normalizedEmail = normalizeEmail(request.getEmail());

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.isEnabled()) {
            throw new RuntimeException("Please verify OTP first");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        return user;
    }

    private String normalizeEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new RuntimeException("Email is required");
        }
        return email.trim().toLowerCase();
    }

    private String generateOtp() {
        return String.valueOf(100000 + new Random().nextInt(900000));
    }

    private void sendOtpEmail(String email, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(mailFrom);
            message.setTo(email);
            message.setSubject("HealthHub OTP Verification");
            message.setText("Your OTP is: " + otp + ". It is valid for 5 minutes.");
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send OTP email. Check SMTP configuration.");
        }
    }
}