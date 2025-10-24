package com.eventhub.ApiGateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret;

    public String getTokenFromRequest(ServerHttpRequest request) {
        String header = request.getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer")) {
            return header.substring(7);
        }
        return null;
    }


    public boolean validateJwtToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!new Date().before(claims.getExpiration())) return false;
            return claims.get("type").toString().equals("access");

        } catch (Exception e) {
            System.out.println("Ошибка при парсинге jwt");
        }

        return false;
    }


    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(secret)
        );
    }
}
