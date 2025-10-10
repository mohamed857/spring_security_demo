package com.sc.spring_sec_demo.service;

import com.sc.spring_sec_demo.dao.UserRepo;
import com.sc.spring_sec_demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepo repo;
    private final BCryptPasswordEncoder encoder;

    @Autowired
    public UserService(UserRepo repo, BCryptPasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }
    public User saveUSer(User user){
        user.setPassword(encoder.encode(user.getPassword()));
        return repo.save(user);
    }
}
