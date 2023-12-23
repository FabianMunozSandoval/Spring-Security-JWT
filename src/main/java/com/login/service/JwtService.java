package com.login.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    //256 bit 32 byte password
    private static final String SECRET_KEY = "930e84860b8fc2fbe7da1683bd10d6d4c3d2b05aae7b99669f4fba0e8444ed03";

    //sobrecarga del metodo generate token para cargar solo con userDetails
    //para no usar los extraClaims
    public String generateToken(UserDetails userDetails)
    {
        return generateToken(new HashMap<>(), userDetails);
    }

    //Metodo para generar el token a partir de los userDetails
    //y reclamaciones extra si es que las hay
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails)
    {
        return Jwts.builder().setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                .signWith(getSingInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //metodo para extraer nombre de usuario del token
    public String getUserName(String token)
    {
        return getClaims(token, Claims::getSubject);
    }


    //metodo generico para extraer toda la info del token
    public <T> T getClaims(String token, Function<Claims, T> claimsResolver)
    {
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //Metodo para analizar la autenticidad del token con la clave de la firma
    //y obtener las reclamaciones del token si esta autenticado
    private Claims getAllClaims(String token)
    {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSingInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //Metodo para decodificar la secret key en base 64
    //y transformarla en en una clave HMAC que es la que se utiliza para firmar los jwt
    private Key getSingInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //Metodo boolean para validar el token con las siguientes condiciones
    //si el usuario enviado en el token es igual al usuario almacenado en DB
    //y si el token no la expirado devolvera un true
    public boolean validateToken(String token, UserDetails userDetails)
    {
        final String username = getUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    //Metodo para comprobar que el token no a expirado comparando la fecha del token con la fecha del pc
    private boolean isTokenExpired(String token)
    {
        return getExpiration(token).before(new Date());
    }

    //Metodo para extraer la fecha de expiracion de el token
    private Date getExpiration(String token)
    {
        return getClaims(token, Claims::getExpiration);
    }

}
