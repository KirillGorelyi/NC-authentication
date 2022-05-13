package org.nc.authentication.config;

import org.nc.core.entity.UserEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<UserEntity, String> {
    boolean existsByUsername(String userName);
    Optional<UserEntity> findByUsername(String userName);
    Optional<UserEntity> findByUsernameAndPassword(String userName, String password);

}
