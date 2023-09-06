package com.pial.springsecuritytask.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class UserDto {
    private long id;
    private String userId;
    private String email;
    private String password;

    public void setAccessToken(String s) {
    }
}


