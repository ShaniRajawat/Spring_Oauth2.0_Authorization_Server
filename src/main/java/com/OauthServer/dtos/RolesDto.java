package com.OauthServer.dtos;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RolesDto {
    private String roleId;
    private String roleName;
}
