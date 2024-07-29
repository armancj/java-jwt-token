package com.gdai.security.auth;

import com.gdai.security.config.JwtService;
import com.gdai.security.user.Role;
import com.gdai.security.user.User;
import com.gdai.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        User createUser = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(this.passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        this.userRepository.save(createUser);

        return getAuthenticationResponse(createUser);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())
        );

        User getUser = this.userRepository.findByEmail(request.getEmail()).orElseThrow();
        return getAuthenticationResponse(getUser);

    }

    private AuthenticationResponse getAuthenticationResponse(User user) {
        String jwtToken = this.jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
