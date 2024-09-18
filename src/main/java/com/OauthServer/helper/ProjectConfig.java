package com.OauthServer.helper;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ProjectConfig {

    @Bean
    public ModelMapper mapper(){
        return new ModelMapper();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


//    Steps for token
//    Authorization Code URL
//    http://localhost:8081/oauth2/authorize?response_type=code&client_id=client&scope=read
//    Token EndPoint
//    http://localhost:9092/oauth2/token
//    Now in Authorization choose basic auth and fill these
//    client=client
//    secret=secret
//    and get the token and fetch any protected api you want

}
