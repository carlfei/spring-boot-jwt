package com.simple.filter;

import com.simple.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtFilter extends BasicAuthenticationFilter {

    // Nombre del encabezado de autorización
    public static final String AUTHORIZATION = "Authorization";

    @Autowired
    private JwtService jwtService;

    public JwtFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        // Obtener el encabezado de autorización de la solicitud
        String authHeader = request.getHeader(AUTHORIZATION);

        // Comprobar si el encabezado es nulo o no es un token Bearer
        if (authHeader == null || !jwtService.isBearer(authHeader)) {
            filterChain.doFilter(request,response);
            return;
        }
        try {
            // Intentar autenticar al usuario utilizando el token JWT
            UsernamePasswordAuthenticationToken authentication = getAuthentication(authHeader);
            if (authentication != null) {
                filterChain.doFilter(request, response);
                return;
            }
            // Devolver un error 401 (no autorizado) si el token no es válido
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
        } catch (Exception ex) {
            // Devolver un error 500 (error interno del servidor) si se produce un error al procesar el token
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred while processing the token");
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String authHeader) {
        // Obtener el usuario y los roles del token JWT utilizando la instancia JwtService
        String user = jwtService.getUserFromToken(authHeader);
        List<String> roles = jwtService.getRolesFromToken(authHeader);

        // Crear una lista de GrantedAuthority a partir de los roles
        List<GrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        // Devolver una instancia de UsernamePasswordAuthenticationToken con el usuario y las autoridades
        return new UsernamePasswordAuthenticationToken(user, null, authorities);
    }
}
