package com.login.service;

import com.login.model.AuthResponse;
import com.login.model.AuthenticationRequest;
import com.login.model.RegisterRequest;

public interface AuthService {

    AuthResponse register (RegisterRequest request);

    AuthResponse authenticate (AuthenticationRequest request);

}
