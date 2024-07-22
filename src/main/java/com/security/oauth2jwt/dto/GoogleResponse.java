package com.security.oauth2jwt.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@Data
@RequiredArgsConstructor
public class GoogleResponse implements OAuth2Response{

    private final Map<String, Object> attribute;

    @Override
    public String getProvider() {

        return "google";
    }

    @Override
    public String getProviderId() {

        return attribute.get("sub").toString();
    }

    @Override
    public String getEmail() {

        return attribute.get("email").toString();
    }

    @Override
    public String getName() {

        return attribute.get("name").toString();
    }
}
