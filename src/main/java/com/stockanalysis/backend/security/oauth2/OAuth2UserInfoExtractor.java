package com.stockanalysis.backend.security.oauth2;

import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuth2UserInfoExtractor {
    OAuth2UserInfo extractUserInfo(OAuth2User oAuth2User);
}
