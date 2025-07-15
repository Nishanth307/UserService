package com.nishanth.UserService.security;

import com.nishanth.UserService.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.nishanth.UserService.models.User;

import java.util.Optional;

@Service
public class CustomSpringUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    public CustomSpringUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User>  user = userRepository.findByEmail(username);
        if (user.isEmpty()){
            throw new UsernameNotFoundException("user Not Found");
        }
        User savedUser = user.get();
        return new CustomSpringUserDetails(savedUser);
    }
}
