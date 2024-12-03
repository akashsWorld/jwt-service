package com.cromxt.jwt;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JWTService {
    String extractUsername(String token);
    String generateAccessToken(UserDetails userDetails,Map<String, Object> extraClaims);
    String generateRefreshToken(UserDetails userDetails);
    Boolean isTokenValid(String token, UserDetails userDetails);

}