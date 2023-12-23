package com.login.config;

import com.login.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationAdapter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //Obtiene el header Authorization que trae jwt
        final String authHeader = request.getHeader("Authorization");

        final String jwt;
        final String userName;

        //Validacion para comprobar que el authHeader no sea nulo y que en authHeader contenga el string bearer
        //si no se cumplen devuelve el control al filtro
        if (authHeader == null || !authHeader.startsWith("Bearer"))
        {
            filterChain.doFilter(request, response);
            return;
        }

        //En caso de cumplir lo anterior

        //extrae el jwt desde el caracter 7 en adelante
        jwt = authHeader.substring(7);
        //extrae el username del jwt enviado
        userName = jwtService.getUserName(jwt);

        //Comprobacion de que el username no  sea nulo
        //y que no haya otra autenticacion en curso para ese usuario
        if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null)
        {
            //carga los datos del usuario como los permisos, roles, etc
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userName);
            //valida que el token contenga los datos que estan almacenados en la DB
            if (jwtService.validateToken(jwt,userDetails))
            {
                //establece la autenticacion del usuario con sus permisos
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
