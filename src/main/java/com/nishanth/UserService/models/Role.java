package com.nishanth.UserService.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
//@JsonDeserialize(as = Role.class)
public class Role extends BaseModel {
    @Column(unique = true)
    private String role;
}
