package com.OauthServer.controller;



import com.OauthServer.exception.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.*;
import com.OauthServer.services.OtpService;


@RestController
@RequestMapping("/otp")
public class OtpController {

    private final Logger logger = LoggerFactory.getLogger(OtpController.class);

    @Autowired
    private OtpService otpService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private HttpSessionSecurityContextRepository securityContextRepository;

    private final HttpSessionRequestCache cache = new HttpSessionRequestCache();
//    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    @GetMapping("/generate")
    public String generateOtp(@RequestParam String mobile) {
        String otp = otpService.generateOtp(mobile);
        return "OTP generated and sent to your mobile number: " + otp;
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginWithOtp(@RequestParam String mobile, @RequestParam String otp, HttpServletRequest request, HttpServletResponse response) {
        try {
            if (!(otpService.validateOtp(mobile,otp))){
                throw new ResourceNotFoundException("Invalid OTP");
            }

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(mobile, otp);

            Authentication authentication = authenticationManager.authenticate(authToken);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            HttpSession session = request.getSession(true);
            logger.info("Session ID: {}", session.getId());

            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
            logger.info("Saving Context in the Session");

            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
            logger.info("Saving Context in the SecurityContextHolder");

            logger.info("Authentication successful for mobile: {}", mobile);
            SavedRequest savedRequest = cache.getRequest(request, response);

            if (savedRequest != null) {
                String url = savedRequest.getRedirectUrl();
                logger.info("The redirect URI is {} \n Redirecting to Url with help of PageUI",url);
//                redirectStrategy.sendRedirect(request, response, targetUrl);
                return new ResponseEntity<>(url, HttpStatus.OK);
            } else {
                String url = "http://localhost:9091/";
//                String url = "https://accounts-preview.omnileadz.com/home";
            }

        } catch (Exception e) {
            return new ResponseEntity<>("Invalid OTP !!!",HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>("Invalid OTP !!!",HttpStatus.UNAUTHORIZED);
    }
}

