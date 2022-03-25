package com.mbsystems.securitydemo01.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> applicationUserByUserName(String userName);
}
