package com.nishanth.UserService.exceptions;

public class LoginLimitReachedException extends RuntimeException{
    private String message;
    public LoginLimitReachedException(String message){
        super(message);
    }
}
