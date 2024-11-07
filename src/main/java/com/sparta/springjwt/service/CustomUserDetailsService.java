package com.sparta.springjwt.service;

import com.sparta.springjwt.dto.CustomUserDetails;
import com.sparta.springjwt.entity.UserEntity;
import com.sparta.springjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    UserEntity userEntity = userRepository.findByUsername(username);
    if (userEntity != null) {

      return new CustomUserDetails(userEntity);
    }
    return null;
  }
}
