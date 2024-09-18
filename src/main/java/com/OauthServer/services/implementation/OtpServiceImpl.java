package com.OauthServer.services.implementation;

import com.OauthServer.repository.UserRepository;
import com.OauthServer.services.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class OtpServiceImpl implements OtpService {
    @Autowired
    private UserRepository userRepository;
    private Map<String, String> otpStorage = new HashMap<>();

    @Override
    public String generateOtp(String mobile) {
        if(userRepository.findByMobile(mobile)==null){
            throw new NullPointerException("User is not found with given mobile : "+mobile);
        }
        String otp = String.valueOf(new Random().nextInt(999999));
        otpStorage.put(mobile, otp);
        return otp;
    }

    @Override
    public boolean validateOtp(String mobile, String otp) {
        return otpStorage.containsKey(mobile) && otpStorage.get(mobile).equals(otp);
    }
}

