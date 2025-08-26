package com.app.config;

import java.util.Arrays; // ADD THIS IMPORT
import java.util.List;   // ADD THIS IMPORT

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration; // ADD THIS IMPORT
import org.springframework.web.cors.CorsConfigurationSource; // ADD THIS IMPORT
import org.springframework.web.cors.UrlBasedCorsConfigurationSource; // ADD THIS IMPORT

import com.app.security.JWTFilter;
import com.app.services.UserDetailsServiceImpl;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	@Autowired
	private JWTFilter jwtFilter;

	@Autowired
	private UserDetailsServiceImpl userDetailsServiceImpl;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.cors() // ADD THIS LINE TO ENABLE CORS
				.and()  // ADD THIS LINE TO CONTINUE THE CHAIN
				.csrf()
				.disable()
				.authorizeHttpRequests()
				.requestMatchers("/login.html", "/api/register").permitAll()
				.requestMatchers(AppConstants.PUBLIC_URLS).permitAll()
				.requestMatchers(AppConstants.USER_URLS).hasAnyAuthority("USER", "ADMIN")
				.requestMatchers(AppConstants.ADMIN_URLS).hasAuthority("ADMIN")
				.anyRequest()
				.authenticated()
				.and()
				.exceptionHandling().authenticationEntryPoint(
						(request, response, authException) ->
								response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

		http.authenticationProvider(daoAuthenticationProvider());

		DefaultSecurityFilterChain defaultSecurityFilterChain = http.build();

		return defaultSecurityFilterChain;
	}

	// ADD THIS ENTIRE BEAN TO CONFIGURE CORS
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		// This allows requests from any origin. For production, you might want to restrict this.
		configuration.setAllowedOrigins(List.of("*"));
		// This allows all standard HTTP methods.
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		// This allows all headers.
		configuration.setAllowedHeaders(List.of("*"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		// This applies the CORS configuration to all paths in your application.
		source.registerCorsConfiguration("/**", configuration);

		return source;
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

		provider.setUserDetailsService(userDetailsServiceImpl);
		provider.setPasswordEncoder(passwordEncoder());

		return provider;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}
}