package com.codigoprueba.pruebatrabajo.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationProvider;

import com.codigoprueba.pruebatrabajo.JWT.JWTAutheticationFilter;


import lombok.RequiredArgsConstructor;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig  {
    
    private final JWTAutheticationFilter jwtAutheticationFilter;
    private final AuthenticationProvider authProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf ->
                csrf
                .disable())
            .authorizeHttpRequests(authRequest -> 
            authRequest
            .requestMatchers("/auth/**").permitAll()
            .requestMatchers("/Consultar/**").permitAll()
            .requestMatchers("/Buscar/**").permitAll()
            .anyRequest().authenticated()
            )
            .sessionManagement(sessionManagement ->
            sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authProvider)
            .addFilterBefore(jwtAutheticationFilter, UsernamePasswordAuthenticationFilter.class)    
            .build();
    }   

        }
