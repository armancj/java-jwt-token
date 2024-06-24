package com.gdai.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY= "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";


    public String extractUserName(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }


    private Claims extractAllClaims(String jwt) {
        return Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(jwt).getPayload();
    }

    public <T> T extractClaim(String jwt, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }

    private static SecretKey getSignInKey() {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);

    }

    public boolean isTokenValid(String jwt, UserDetails userDetails ){
        final String username = extractUserName(jwt);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(jwt));
    }

    private boolean isTokenExpired(String jwt) {
        assert extractExpiration(jwt) != null;
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt, Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .signWith(getSignInKey(), Jwts.SIG.HS256)
                .claims()
                .empty()
                .add(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 24))
                .and().compact();
    }
}
