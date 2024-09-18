package com.OauthServer.SpringOauthServer;

import java.util.ArrayList;

public class Name {



    public static void main(String[] args) {
        ArrayList<String> names = new ArrayList<>();

        names.add("shani");
        names.add("honey");
        names.add("suraj");
        names.add("satyam");
        names.add("ulllas");

        int count = 0;
        for (int i = 0; i < names.size()-1; i++) {
            String name = names.get(i);
            if (name.startsWith("s")) {
                System.out.println(name);
                count++;
            }
        }
        System.out.println(count);
    }
}
