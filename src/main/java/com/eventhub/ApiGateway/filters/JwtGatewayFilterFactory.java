package com.eventhub.ApiGateway.filters;

import com.eventhub.ApiGateway.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtGatewayFilterFactory extends AbstractGatewayFilterFactory {

    @Autowired
    private JwtService jwtService;

    @Override
    public GatewayFilter apply(Object config) {
        return ((exchange, chain) -> {
            System.out.println("[FILTER] -> Сработал фильтр в какой то момент запроса");

            String accessToken = jwtService.getTokenFromRequest(exchange.getRequest());
            if (accessToken == null || !jwtService.validateJwtToken(accessToken)) {
                exchange.getResponse()
                        .setStatusCode(HttpStatus.UNAUTHORIZED);

                return exchange.getResponse().setComplete();
            }

            return chain.filter(exchange);
        });
    }
}
