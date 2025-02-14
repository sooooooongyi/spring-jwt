package com.sparta.springjwt.config;

import com.sparta.springjwt.jwt.JWTFilter;
import com.sparta.springjwt.jwt.JWTUtil;
import com.sparta.springjwt.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
  private final AuthenticationConfiguration authenticationConfiguration;
  private final JWTUtil jwtUtil;

  public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

    this.authenticationConfiguration = authenticationConfiguration;
    this.jwtUtil = jwtUtil;
  }

  //AuthenticationManager Bean 등록
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
      throws Exception {

    return configuration.getAuthenticationManager();
  }


  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {

    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    //csrf disable
    http
        .csrf((auth) -> auth.disable());

    //From 로그인 방식 disable
    http
        .formLogin((auth) -> auth.disable());

    //http basic 인증 방식 disable
    http
        .httpBasic((auth) -> auth.disable());

    http.authorizeHttpRequests((auth) -> auth
            .requestMatchers("/").permitAll()
            .requestMatchers("/admin").hasRole("ADMIN")
            .requestMatchers("/login", "/join").permitAll()
//        .requestMatchers("/admin").hasRole("ADMIN")
            .anyRequest().authenticated()
    );

    http
        .sessionManagement((session) -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http
        .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
    http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil),
        UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}
