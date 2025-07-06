package com.stockanalysis.backend.security.oauth2;

import org.springframework.security.oauth2.core.user.OAuth2User;

public class FacebookOAuth2UserInfoExtractor implements OAuth2UserInfoExtractor {

    @Override
    public OAuth2UserInfo extractUserInfo(OAuth2User oAuth2User) {
        return new FacebookOAuth2UserInfo(oAuth2User.getAttributes());
    }
}
