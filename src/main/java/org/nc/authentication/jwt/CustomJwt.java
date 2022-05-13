package org.nc.authentication.jwt;

import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

public class CustomJwt extends Jwt {
    public CustomJwt(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> headers, Map<String, Object> claims) {
        super(tokenValue, issuedAt, expiresAt, headers, claims);
    }

    public CustomJwt(Jwt jwt){
        super(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getHeaders(), jwt.getClaims());
    }

    public boolean isExpired(){
        assert !(super.getExpiresAt() ==null);
        return getExpiresAt().isBefore(Instant.now());
    }

    private static Map<String, Object> getHeaderMap(){
        return new HashMap<>(){{
            put("username", "username");
        }};
    }

    private static Map<String, Object> getClaimsMap(String username){
        return new HashMap<>(){{
            put("username", username);
            put("role", "role");
        }};
    }


    public static CustomJwt generateJWT(String login){
        var jwt = new CustomJwt(
                "AUTHORIZED",
                Instant.now(),
                Instant.now().plus(1, ChronoUnit.HOURS),
                getHeaderMap(),
                getClaimsMap(login));
        return jwt;
    }

    @Override
    public String toString(){
        return super.toString();
    }

}
