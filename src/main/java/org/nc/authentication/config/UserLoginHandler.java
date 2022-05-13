package org.nc.authentication.config;

import org.nc.authentication.entities.ApiResponse;
import org.nc.authentication.entities.LoginRequest;
import org.nc.authentication.entities.LoginResponse;
import org.nc.authentication.jwt.TokenProvider;
import org.nc.core.config.security.PasswordEncryptor;
import org.nc.core.config.security.roles.RoleEnum;
import org.nc.core.entity.UserEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import static org.springframework.http.MediaType.APPLICATION_JSON;

@Component
public class UserLoginHandler {
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final PasswordEncryptor encryptor;
    private volatile UserEntity userEntity;

    public UserLoginHandler(UserRepository userRepository, TokenProvider tokenProvider, PasswordEncryptor encryptor) {
        this.userRepository = userRepository;
        this.tokenProvider = tokenProvider;
        this.encryptor = encryptor;
    }

    public Mono<ServerResponse> login(ServerRequest request) {
        request.exchange();
        var loginRequest = request.bodyToMono(LoginRequest.class);
        return loginRequest
                .publishOn(Schedulers.boundedElastic())
                .doOnSuccess(login -> userEntity = userRepository.findByUsername(login.getUsername()).orElseThrow())
                .flatMap(login -> {
                    if (encryptor.match(login.getPassword(),userEntity.getPassword())) {
                        return ServerResponse
                                .ok()
                                .contentType(APPLICATION_JSON)
                                .body(BodyInserters.fromObject(
                                        new LoginResponse(tokenProvider.generateToken(userEntity))));
                    } else {
                        return ServerResponse.badRequest().body(BodyInserters.fromObject(new ApiResponse(400, "Invalid credentials", null)));
                    }
                });
    }

    public Mono<ServerResponse> signUp(ServerRequest request) {
        Mono<UserEntity> userMono = request.bodyToMono(UserEntity.class);
        return userMono.map(user -> {
            user.setPassword(encryptor.encryptPassword(user.getPassword()));
            return user;
        }).publishOn(Schedulers.boundedElastic()).publishOn(Schedulers.boundedElastic()).flatMap(user -> {
            var userEntity = userRepository.findByUsername(user.getUsername());
            if (userEntity.isPresent()) return ServerResponse.badRequest().
                    body(BodyInserters.fromObject(new ApiResponse(400, "Username is not unique", null)));
            user.addRole(RoleEnum.USER);
            var newUser = userRepository.save(user);
            return ServerResponse
                    .ok()
                    .contentType(APPLICATION_JSON)
                    .body(BodyInserters.fromObject(
                            new LoginResponse(tokenProvider.generateToken(newUser))));
        });
    }

}
