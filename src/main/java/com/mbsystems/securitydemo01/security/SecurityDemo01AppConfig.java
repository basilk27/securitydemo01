package com.mbsystems.securitydemo01.security;

import com.mbsystems.securitydemo01.auth.ApplicationUserDetailsService;
import com.mbsystems.securitydemo01.jwt.JwtConfig;
import com.mbsystems.securitydemo01.jwt.JwtSecretKey;
import com.mbsystems.securitydemo01.jwt.JwtTokenVerifier;
import com.mbsystems.securitydemo01.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.concurrent.TimeUnit;

import static com.mbsystems.securitydemo01.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityDemo01AppConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserDetailsService applicationUserDetailsService;
    private final JwtSecretKey jwtSecretKey;
    private final JwtConfig jwtConfig;

    public SecurityDemo01AppConfig(PasswordEncoder passwordEncoder,
                                   ApplicationUserDetailsService applicationUserDetailsService,
                                   JwtSecretKey jwtSecretKey,
                                   JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserDetailsService = applicationUserDetailsService;
        this.jwtSecretKey = jwtSecretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())   //bmk use this when it is browser
//                .and()
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), this.jwtSecretKey))
                .addFilterAfter(new JwtTokenVerifier(this.jwtSecretKey, jwtConfig),
                                                    JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/ja/*")
                    .permitAll()
                .antMatchers("/api/v1/students").hasRole(STUDENT.name())
                //.antMatchers(HttpMethod.DELETE,"/api/v1/admin/**").hasAnyAuthority(COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.POST,"/api/v1/admin/**").hasAnyAuthority(COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.PUT,"/api/v1/admin/**").hasAnyAuthority(COURSE_WRITE.getPermission())
                //.antMatchers(HttpMethod.GET,"/api/v1/admin/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated();
//                .and()
//                .formLogin()
//                .loginPage("/login").permitAll()
//                .defaultSuccessUrl("/courses", true)
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//                    .key("somekey")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login");
//                //.httpBasic(); // use this for Basic auth

    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails annaSmith = User.builder()
//                .username("annasmith")
//                .password(passwordEncoder.encode("password"))
//                //.roles(STUDENT.name())
//                .authorities(STUDENT.getGrantedAuthority())
//                .build();
//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
//                //.roles(ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthority())
//                .build();
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password123"))
//                //.roles(ADMIN_TRAINEE.name())
//                .authorities(ADMIN_TRAINEE.getGrantedAuthority())
//                .build();
//
//        return new InMemoryUserDetailsManager( annaSmith, lindaUser, tomUser );
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider( daoAuthenticationProvider() );
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setPasswordEncoder( this.passwordEncoder );
        provider.setUserDetailsService( this.applicationUserDetailsService );

        return provider;
    }
}
