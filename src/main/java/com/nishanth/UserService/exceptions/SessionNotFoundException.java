package com.nishanth.UserService.exceptions;

public class SessionNotFoundException extends RuntimeException{
    private String message;
    public SessionNotFoundException(String message){
        super(message);
    }
}
