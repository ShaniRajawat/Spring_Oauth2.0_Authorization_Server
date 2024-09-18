package com.OauthServer.dtos;

import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
        private String userId;

        private String name;

        private String email;

        private String password;

        private  String gender;

        private String about;

        private String imageName;

        private Set<RolesDto> roles = new HashSet<>();
}
