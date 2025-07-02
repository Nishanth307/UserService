package com.nishanth.UserService.services;

import com.nishanth.UserService.dtos.UserDto;
import com.nishanth.UserService.exceptions.IncorrectPasswordException;
import com.nishanth.UserService.exceptions.LoginLimitReachedException;
import com.nishanth.UserService.exceptions.SessionNotFoundException;
import com.nishanth.UserService.exceptions.UserNotFoundException;
import com.nishanth.UserService.models.Session;
import com.nishanth.UserService.models.SessionStatus;
import com.nishanth.UserService.models.User;
import com.nishanth.UserService.repositories.SessionRepository;
import com.nishanth.UserService.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMapAdapter;

import javax.crypto.SecretKey;
import java.time.LocalDate;
import java.util.*;

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
        List<Session> activeSessions = sessionRepository.findAllByUserIdAndSessionStatus(user.getId(), SessionStatus.ACTIVE);
        if (activeSessions.size()>=2){
            throw new LoginLimitReachedException("Login limit Reached more than 2");
        }

        //jwt token
        MacAlgorithm algo = Jwts.SIG.HS256; // Hashing algo
        SecretKey key = algo.key().build(); // Secret Key
        Map<String,Object> jsonForJwt = new HashMap<>();
        jsonForJwt.put("email",user.getEmail());
        jsonForJwt.put("roles",user.getRoles());
        jsonForJwt.put("createdAt",new Date());
        jsonForJwt.put("expiredAt",new Date(LocalDate.now().plusDays(3).toEpochDay()));

        String token = Jwts.builder()
                .claims(jsonForJwt) // added claims
                .signWith(key, algo) //added key
                .compact(); // building the token

        Session session = new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(token);
        session.setUser(user);
        session.setLoginAt(new Date());
        sessionRepository.save(session);

        UserDto userDto = UserDto.from(user);
        MultiValueMapAdapter<String,String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE,token);
        return new ResponseEntity<>(userDto,headers, HttpStatus.OK);
    }

    public ResponseEntity<Void> logout(String token, Long userId) {
        Optional<Session> optionalSession = sessionRepository.findByTokenAndUser_Id(token,userId);
        List<Session> activeSessions = sessionRepository.findAllByUserIdAndSessionStatus(userId, SessionStatus.ACTIVE);
        if (optionalSession.isEmpty() || activeSessions.isEmpty()){
            throw new SessionNotFoundException("No active Sessions");
        }

        Session session = optionalSession.get();
        session.setSessionStatus(SessionStatus.ENDED);
        sessionRepository.save(session);
        return ResponseEntity.ok().build();
    }

    public SessionStatus validate(String token, Long userId) {
        //check expiry // Jwts Parser -> parse the encoded JWT token to read the claims
        MacAlgorithm algo = Jwts.SIG.HS256; // Hashing algo
        SecretKey key = algo.key().build();
        Claims claims = Jwts.parser()
                .verifyWith(key).build()
                .parseSignedClaims(token)
                .getPayload();
        if (claims.getExpiration().before(new Date())){
            throw new SessionNotFoundException("Token has expired");
        }
        Optional<Session> optionalSession = sessionRepository.findByTokenAndUser_Id(token, userId);
        if (optionalSession.isEmpty() || optionalSession.get().getSessionStatus().equals(SessionStatus.ENDED)){
            throw new SessionNotFoundException("Token is invalid");
        }
        return SessionStatus.ACTIVE;
    }
}

/*
    MultiValueMapAdapter is map with single key and multiple values
    Headers
    Key     Value
    Token   """
    Accept  application/json, text, images
 */