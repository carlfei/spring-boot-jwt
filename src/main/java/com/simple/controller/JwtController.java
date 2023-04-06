package com.simple.controller;

import com.simple.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping(JwtController.JWTURI)
public class JwtController {
    public static final String TOKENURI = "/token";
    public static final String JWTURI = "/jwt";

    @Autowired
    private JwtService jwtService;

    // Este endpoint requiere autenticación
    // y devuelve un token JWT para el usuario autenticado
    @PreAuthorize("authenticated")
    @GetMapping(value = TOKENURI)
    public String login(@AuthenticationPrincipal User user){
        // Obtener los roles del usuario autenticado
        List<String> roles = user.getAuthorities().stream().map(
                a->a.getAuthority()).collect(Collectors.toList());
        // Crear el token JWT para el usuario
        return jwtService.createToken(user.getUsername(),roles);

    }

    // Este endpoint requiere que el usuario tenga el rol "USER"
    // y devuelve un mensaje indicando que el acceso fue exitoso
    @PreAuthorize("hasRole('USER')")
    @GetMapping
    public String verify(){
        return "acceso exitoso";
    }
}