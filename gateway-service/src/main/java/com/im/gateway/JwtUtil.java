package com.im.gateway;
import io.jsonwebtoken.*; import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value; import org.springframework.stereotype.Component;
import javax.annotation.PostConstruct; import java.security.Key; import java.time.Instant; import java.util.Date;
@Component
public class JwtUtil {
  @Value("${jwt.secret}") private String secret;
  @Value("${jwt.issuer}") private String issuer;
  @Value("${jwt.exp-min}") private long expMin;
  private Key key;
  @PostConstruct void init(){ key = Keys.hmacShaKeyFor(secret.getBytes()); }
  public String create(String sub){
    Instant now = Instant.now();
    return Jwts.builder().setSubject(sub).setIssuer(issuer)
      .setIssuedAt(Date.from(now)).setExpiration(Date.from(now.plusSeconds(expMin*60)))
      .signWith(key, SignatureAlgorithm.HS256).compact();
  }
  public Jws<Claims> parse(String token){ return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); }
}
