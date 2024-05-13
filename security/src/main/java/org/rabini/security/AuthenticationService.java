package org.rabini.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public AuthenticationResponse register(RegisterRequest request) {
		var user = User.builder().firstname(request.getFirstname()).lastName(request.getLastname())
				.email(request.getEmail()).pass(passwordEncoder.encode(request.getPassword())).role(Role.USER)
				.build();
		repository.save(user);
		var token = jwtService.generateToken(user);

		return AuthenticationResponse.builder().token(token).build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		var user = repository.findByEmail(request.getEmail()).orElseThrow();
		var token = jwtService.generateToken(user);
		return AuthenticationResponse.builder().token(token).build();
	}
}
