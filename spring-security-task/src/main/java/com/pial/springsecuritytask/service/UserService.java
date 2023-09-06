package com.pial.springsecuritytask.service;


import com.pial.springsecuritytask.model.UserDto;

public interface UserService {
    UserDto createUser(UserDto user) throws Exception;
    UserDto getUser(String email);

    UserDto getUserByUserId(String id) throws Exception;

}