package com.simple.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    // Constantes para la configuración de JWT
    private static final String ISSUER = "issuer-spring";
    private static final String SECRET = "key-secret";
    private static final long EXPIRATION_TIME_MS = 7200000L; // 2 hours

    // Método para crear un token JWT basado en la información y los roles del usuario
    public String createToken(String user, List<String> roles) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET); //lgoritmo HMAC256 con la clave secreta
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + EXPIRATION_TIME_MS); // Establecer el tiempo de caducidad del token
        return JWT.create()
                .withIssuer(ISSUER)
                .withIssuedAt(now)
                .withExpiresAt(expirationTime)
                .withClaim("user", user)
                .withArrayClaim("roles", roles.toArray(new String[0])) // Add user roles to the token
                .sign(algorithm);
    }

    // verificar si el encabezado de autorización es un token de portador
    public boolean isBearer(String authorizationHeader) {
        return authorizationHeader != null &&
                authorizationHeader.startsWith("Bearer ") &&
                authorizationHeader.split("\\.").length == 3;
    }

    // Método para obtener al usuario del token JWT(masculino)
    public String getUserFromToken(String authorizationHeader) {
        DecodedJWT jwt = verifyToken(authorizationHeader); // Verificar el token antes de extraer la información del usuario
        return jwt.getClaim("user").asString();
    }

    // obtener los roles del token JWT
    public List<String> getRolesFromToken(String authorizationHeader) {
        DecodedJWT jwt = verifyToken(authorizationHeader); // Verify the token before extracting role information
        return jwt.getClaim("roles").asList(String.class);
    }

    // verificar el token JWT y devolver el JWT decodificado
    private DecodedJWT verifyToken(String authorizationHeader) {
        if (!isBearer(authorizationHeader)) {
            throw new IllegalArgumentException("Authorization header is not valid");
        }

        String token = authorizationHeader.replace("Bearer ", ""); //Eliminar "Bearer" del encabezado de autorización para obtener el token

        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET); //algoritmo HMAC256 con la clave secreta para la verificación
            return JWT.require(algorithm)
                    .withIssuer(ISSUER)
                    .build()
                    .verify(token); // Verificar el token utilizando el algoritmo y el emisor especificados
        } catch (JWTVerificationException ex) {
            throw new IllegalArgumentException("Token is not valid", ex);
        }
    }
}
