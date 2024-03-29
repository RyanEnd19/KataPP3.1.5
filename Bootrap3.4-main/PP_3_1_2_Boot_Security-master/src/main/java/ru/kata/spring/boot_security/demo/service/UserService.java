package ru.kata.spring.boot_security.demo.service;


import ru.kata.spring.boot_security.demo.dto.UserDto;
import ru.kata.spring.boot_security.demo.entity.User;

import java.util.List;
import java.util.Optional;

public interface UserService {
    List<User> getAllUsers();

    User getUserById(Long id);

    void addUser(User user);

    void removeUser(Long id);

    void updateUser(User user);

    Optional<User> findByUsername(String username);

    User convertToUser(UserDto userDto);

    boolean checkPassword(User user, String rawPassword) ;
}