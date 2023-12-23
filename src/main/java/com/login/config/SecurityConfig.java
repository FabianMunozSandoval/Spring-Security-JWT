package com.login.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationAdapter jwtAuthenticationAdapter;

    //Metodo de filtros http para dar autorizacion con roles y publicos
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
        http
                .authorizeHttpRequests((authz -> authz
                        .requestMatchers("/", "/resources/**", "/css/**", "/js/**", "/images/**",
                                "/api/auth/**").permitAll()
                        //.requestMatchers("/getAllUser/**").hasRole("USER")
                        //.requestMatchers("/getById/**").hasRole("USER")
                        //.requestMatchers("/createUser/**").hasRole("ADMIN")
                        //.requestMatchers("/updateUser/**").hasRole("ADMIN")
                        //.requestMatchers("/deleteUser/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                ))
                .csrf(csrf ->
                        csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationAdapter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    //Actualizar y ajustar segun las nececidades
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // Permite cualquier origen, ajusta según tus necesidades
        configuration.addAllowedMethod("*"); // Permite cualquier método (GET, POST, etc.)
        configuration.addAllowedHeader("*"); // Permite cualquier encabezado

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration); // Ajusta la ruta según tus necesidades

        return source;
    }
}
