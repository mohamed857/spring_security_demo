package com.sc.spring_sec_demo.service;

import com.sc.spring_sec_demo.dao.UserRepo;
import com.sc.spring_sec_demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepo repo;
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    public User saveUSer(User user){
        user.setPassword(encoder.encode(user.getPassword()));
        return repo.save(user);
    }
}
