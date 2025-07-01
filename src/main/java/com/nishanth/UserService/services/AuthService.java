package com.nishanth.UserService.services;

import com.nishanth.UserService.dtos.UserDto;
import com.nishanth.UserService.exceptions.IncorrectPasswordException;
import com.nishanth.UserService.exceptions.SessionNotFoundException;
import com.nishanth.UserService.exceptions.UserNotFoundException;
import com.nishanth.UserService.models.Session;
import com.nishanth.UserService.models.SessionStatus;
import com.nishanth.UserService.models.User;
import com.nishanth.UserService.repositories.SessionRepository;
import com.nishanth.UserService.repositories.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;

import java.util.Date;
import java.util.HashMap;
import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public AuthService(UserRepository userRepository,
                       SessionRepository sessionRepository,
                       BCryptPasswordEncoder bCryptPasswordEncoder){
        this.sessionRepository = sessionRepository;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public UserDto signUp(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        User savedUser = userRepository.save(user);
        return UserDto.from(savedUser);
    }

    public ResponseEntity<UserDto> login(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()){
            throw new UserNotFoundException("User Not Found");
        }
        User user = userOptional.get();
//        if (!Objects.equals(userOptional.get().getPassword(), password))
        if (!bCryptPasswordEncoder.matches(password,user.getPassword())){
            throw new IncorrectPasswordException("Invalid Credentials");
        }
        String token = "abcabc";//jwt token

        Session session = new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(token);
        session.setUser(user);
        session.setLoginAt(new Date());
        sessionRepository.save(session);

        UserDto userDto = UserDto.from(user);
        MultiValueMapAdapter<String,String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE,"auth-token "+token);
        return new ResponseEntity<>(userDto,headers, HttpStatus.OK);
    }

    public ResponseEntity<Void> logout(String token, Long userId) {
        Optional<Session> optionalSession = sessionRepository.findByTokenAndUser_Id(token,userId);
        if (optionalSession.isEmpty()){
            throw new SessionNotFoundException("Session Not Found");
        }
        Session session = optionalSession.get();
        session.setSessionStatus(SessionStatus.ENDED);
        sessionRepository.save(session);
        return ResponseEntity.ok().build();
    }

    public SessionStatus validate(String token, Long userId) {
        if (token==null){return null;}
        if (userId == null){return null;}
        return null;
    }
}

/*
    MultiValueMapAdapter is map with single key and multiple values
    Headers
    Key     Value
    Token   """
    Accept  application/json, text, images
 */