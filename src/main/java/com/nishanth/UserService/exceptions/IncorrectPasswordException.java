package com.nishanth.UserService.exceptions;

public class IncorrectPasswordException extends RuntimeException{
    private String message;
    public IncorrectPasswordException(String message){
        super(message);
    }
}
