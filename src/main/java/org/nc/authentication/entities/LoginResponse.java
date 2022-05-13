package org.nc.authentication.entities;

public class LoginResponse {

    public LoginResponse(String token){
        this.token = token;
    }
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
