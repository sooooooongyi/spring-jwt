package com.sparta.springjwt.repository;

import com.sparta.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

  Boolean existsByUsername(String username);

  UserEntity findByUsername(String username);
}
