package com.stockanalysis.backend.service;

import com.stockanalysis.backend.domain.user.AuthProvider;
import com.stockanalysis.backend.domain.user.User;
import com.stockanalysis.backend.repository.UserRepository;
import com.stockanalysis.backend.security.UserPrincipal;
import com.stockanalysis.backend.security.oauth2.AppleOAuth2UserInfoExtractor;
import com.stockanalysis.backend.security.oauth2.FacebookOAuth2UserInfoExtractor;
import com.stockanalysis.backend.security.oauth2.GoogleOAuth2UserInfoExtractor;
import com.stockanalysis.backend.security.oauth2.LineOAuth2UserInfoExtractor;
import com.stockanalysis.backend.security.oauth2.OAuth2UserInfo;
import com.stockanalysis.backend.security.oauth2.OAuth2UserInfoExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        OAuth2UserInfoExtractor extractor;
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();

        if ("google".equalsIgnoreCase(registrationId)) {
            extractor = new GoogleOAuth2UserInfoExtractor();
        } else if ("facebook".equalsIgnoreCase(registrationId)) {
            extractor = new FacebookOAuth2UserInfoExtractor();
        } else if ("line".equalsIgnoreCase(registrationId)) {
            extractor = new LineOAuth2UserInfoExtractor();
        } else if ("apple".equalsIgnoreCase(registrationId)) {
            extractor = new AppleOAuth2UserInfoExtractor();
        } else {
            throw new OAuth2AuthenticationException("Sorry! Login with " + registrationId + " is not supported yet.");
        }

        OAuth2UserInfo oAuth2UserInfo = extractor.extractUserInfo(oAuth2User);

        if (oAuth2UserInfo.getEmail() == null || oAuth2UserInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
            if (!user.getProvider().equals(AuthProvider.valueOf(registrationId))) {
                throw new OAuth2AuthenticationException("Looks like you're signed up with " +
                        user.getProvider() + " account. Please use your " + user.getProvider() +
                        " account to login.");
            }
            // Update user information if necessary
            user.setUsername(oAuth2UserInfo.getName());
            user.setProviderId(oAuth2UserInfo.getId());
            userRepository.save(user);
        } else {
            user = new User();
            user.setEmail(oAuth2UserInfo.getEmail());
            user.setUsername(oAuth2UserInfo.getName());
            user.setProvider(AuthProvider.valueOf(registrationId));
            user.setProviderId(oAuth2UserInfo.getId());
            userRepository.save(user);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }
}
