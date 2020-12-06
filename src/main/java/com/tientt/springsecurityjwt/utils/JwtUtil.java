package com.tientt.springsecurityjwt.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Service
public class JwtUtil {
    private String SECRET_KEY = "9562b9b48252027553a689723bc2cbb1bfb5b6b1";
    private long EXPIRE_TIME = 1000 * 60 * 60 * 10;

    private Key getKey(){
        byte[] keyByte = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyByte);
    }
    public String generateToken(UserDetails userDetails){
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now+EXPIRE_TIME))
                .signWith(getKey())
                .compact();
    }

    public String getUsername(String jwt){
        return Jwts.parserBuilder().setSigningKey(getKey()).build()
                .parseClaimsJws(jwt).getBody().getSubject();
    }

    public Date getExpireDate(String jwt){
        return Jwts.parserBuilder().setSigningKey(getKey()).build()
                .parseClaimsJws(jwt).getBody().getExpiration();
    }

    public boolean isTokenExpired(String jwt){
        return getExpireDate(jwt).before(new Date());
    }

    public boolean isTokenValidate(String jwt, UserDetails userDetails){
        String username = this.getUsername(jwt);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(jwt);
    }
}
