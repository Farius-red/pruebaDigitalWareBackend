package com.prueba.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwTEntryPoint implements AuthenticationEntryPoint {
    private  final static Logger logger = LoggerFactory.getLogger(JwTEntryPoint.class);

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException e) throws IOException, ServletException {
        logger.error("Fallo el metodo Commence en la clase jwtEntryPoint");

        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "no autorizado");
    }
}
