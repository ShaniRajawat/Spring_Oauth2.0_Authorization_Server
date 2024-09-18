package com.OauthServer.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {
    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @GetMapping("/logoout")
    public String LogoutPage(){
        return "logout";
    }

    @GetMapping("/")
    public String page(){
        return "logout";
    }
}
