package com.mbsystems.securitydemo01.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.mbsystems.securitydemo01.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> applicationUserByUserName(String userName) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> userName.equals( applicationUser.getUsername() ))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        return List.of(
                new ApplicationUser(STUDENT.getGrantedAuthority(), "annasmith",
                                    passwordEncoder.encode("password"), true,
                        true, true, true),
                new ApplicationUser(ADMIN.getGrantedAuthority(), "linda",
                        passwordEncoder.encode("password123"), true,
                        true, true, true),
                new ApplicationUser(ADMIN_TRAINEE.getGrantedAuthority(), "tom",
                        passwordEncoder.encode("password123"), true,
                        true, true, true)
        );
    }
}
