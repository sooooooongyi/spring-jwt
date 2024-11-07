package com.sparta.springjwt.jwt;

import com.sparta.springjwt.dto.CustomUserDetails;
import com.sparta.springjwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JWTFilter extends OncePerRequestFilter {

  private final JWTUtil jwtUtil;

  public JWTFilter(JWTUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String authorization = request.getHeader("Authorization");

    if (authorization == null || !authorization.startsWith("Bearer ")) {

      System.out.println("token null");
      filterChain.doFilter(request, response);

      //조건이 해당되면 메소드 종료 (필수)
      return;
    }

    String token = authorization.split(" ")[1];
    if (jwtUtil.isExpired(token)) {

      System.out.println("token expired");
      filterChain.doFilter(request, response);

      //조건이 해당되면 메소드 종료 (필수)
      return;
    }

    String username = jwtUtil.getUsername(token);
    String role = jwtUtil.getRole(token);

    UserEntity userEntity = new UserEntity();
    userEntity.setUsername(username);
    userEntity.setPassword("temppassword");
    userEntity.setRole(role);

    //UserDetails에 회원 정보 객체 담기
    CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

    //스프링 시큐리티 인증 토큰 생성
    Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null,
        customUserDetails.getAuthorities());
    //세션에 사용자 등록
    SecurityContextHolder.getContext().setAuthentication(authToken);

    filterChain.doFilter(request, response);
  }
}
