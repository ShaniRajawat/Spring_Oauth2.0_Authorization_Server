package com.OauthServer.security.otp;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class OtpAuthenticationToken extends AbstractAuthenticationToken {
    private final String mobile;
    private final String otp;

    public OtpAuthenticationToken(String mobile, String otp) {
        super(null);
        this.mobile = mobile;
        this.otp = otp;
        setAuthenticated(false);
    }

    public OtpAuthenticationToken(String mobile, String otp, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.mobile = mobile;
        this.otp = otp;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return otp;
    }

    @Override
    public Object getPrincipal() {
        return mobile;
    }
}
