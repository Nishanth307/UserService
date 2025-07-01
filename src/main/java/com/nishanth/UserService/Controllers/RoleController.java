package com.nishanth.UserService.Controllers;

import com.nishanth.UserService.models.Role;
import com.nishanth.UserService.services.RoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/roles")
public class RoleController {
    private final RoleService roleService;
    public RoleController(RoleService roleService){
        this.roleService = roleService;
    }

    public ResponseEntity<Role> createRole(String name){
        Role role = roleService.createRole(name);
        return ResponseEntity.ok(role);
    }
}
