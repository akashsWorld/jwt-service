package com.cromxt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;



public class JWTServiceImpl implements JWTService {

//    TODO: Fix the JWT Service Implementation.

    private final String secretKey;
    private final long accessTokenExpiration;
    private final long refreshExpiration;

    public JWTServiceImpl(String secretKey, long accessTokenExpiration, long refreshExpiration) {
        this.secretKey = secretKey;
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshExpiration = refreshExpiration;
    }

    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

//  TODO: To get extra claims later configure it if needed.
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    @Override
    public String generateAccessToken(
            UserDetails userDetails,
            Map<String, Object> extraClaims
    ) {
        return buildToken(extraClaims, userDetails, accessTokenExpiration);
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(),userDetails,refreshExpiration);
    }
    @Override
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && isTokenNonExpired(token);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private boolean isTokenNonExpired(String token) {
        return !extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
