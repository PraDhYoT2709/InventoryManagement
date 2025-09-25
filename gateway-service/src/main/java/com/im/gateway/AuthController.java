package com.im.gateway;
import org.springframework.http.ResponseEntity; import org.springframework.web.bind.annotation.*;
import java.util.Map;
@RestController @RequestMapping("/auth")
public class AuthController {
  private final JwtUtil jwt; public AuthController(JwtUtil j){ this.jwt=j; }
  @PostMapping("/login") public ResponseEntity<?> login(@RequestBody Map<String,String> req){
    String u=req.getOrDefault("username",""); String p=req.getOrDefault("password","");
    if(u.isEmpty()||p.isEmpty()) return ResponseEntity.badRequest().body(Map.of("error","missing creds"));
    return ResponseEntity.ok(Map.of("token", jwt.create(u)));
  }
}
