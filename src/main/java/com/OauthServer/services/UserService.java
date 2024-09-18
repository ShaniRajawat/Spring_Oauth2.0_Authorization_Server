package com.OauthServer.services;

import com.OauthServer.dtos.UserDto;

public interface UserService {

    //get by userId
    UserDto getByUserId(String userId);

    //get single users by email
    UserDto getUserByEmail(String email);


}
