package com.im.gateway;
import io.jsonwebtoken.Claims; import io.jsonwebtoken.Jws;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders; import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component; import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {
  @Autowired private JwtUtil jwt;
  @Override public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain){
    String path = ex.getRequest().getURI().getPath();
    if (path.startsWith("/auth/")) return chain.filter(ex);
    String h = ex.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (h == null || !h.startsWith("Bearer ")) { ex.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED); return ex.getResponse().setComplete(); }
    try {
      Jws<Claims> claims = jwt.parse(h.substring(7));
      ServerHttpRequest mutated = ex.getRequest().mutate().header("X-User", claims.getBody().getSubject()).build();
      return chain.filter(ex.mutate().request(mutated).build());
    } catch (Exception e){ ex.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED); return ex.getResponse().setComplete(); }
  }
  @Override public int getOrder(){ return -1; }
}
