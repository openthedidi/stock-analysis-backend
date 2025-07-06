package com.stockanalysis.backend.security.oauth2;

import java.util.Map;

public class LineOAuth2UserInfo extends OAuth2UserInfo {

    public LineOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("userId");
    }

    @Override
    public String getName() {
        return (String) attributes.get("displayName");
    }

    @Override
    public String getEmail() {
        // LINE API does not provide email by default
        return null;
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("pictureUrl");
    }
}
