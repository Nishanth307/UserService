package com.nishanth.UserService.services;

import com.nishanth.UserService.models.Role;
import com.nishanth.UserService.repositories.RoleRepository;
import org.springframework.stereotype.Service;

@Service
public class RoleService {
    private final RoleRepository roleRepository;
    public RoleService(RoleRepository roleRepository){
        this.roleRepository = roleRepository;
    }

    public Role createRole(String name){
        Role role = new Role();
        role.setRole(name);
        return roleRepository.save(role);
    }
}
