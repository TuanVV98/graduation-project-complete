package com.spring.config;

import com.spring.filters.JwtAuthenticationEntryPointFilter;
import com.spring.filters.JwtAuthenticationTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationEntryPointFilter unauthorizedHandler;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder  )
            throws Exception{
        authenticationManagerBuilder.userDetailsService(this.userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean(){
        return new JwtAuthenticationTokenFilter();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("disable ***");
        http.csrf().disable()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests().antMatchers(
                "/api/v1/user/auth/**","/api/v1/accounts/**","/api/v1/posts/**",
                "/api/v1/vouchers/**","/api/v1/files/**","/api/v1/booking/**","/api/v1/booking/detail/**","/api/v1/comment/**","api/v1/communes/**",
                "/api/v1/customers/**","/api/v1/dentists/**","/api/v1/districts/**","/api/v1/likes/**","/api/v1/provinces/**",
                "api/v1/services/**","/api/v1/schedule-time/**",
                "/v3/api-docs", "/swagger-resources/**", "/swagger-ui/**", "/manage/**").permitAll()

                .antMatchers("/api/v1/vouchers/**","/api/v1/booking/**","/api/v1/booking/detail/**","/api/v1/comment/**","/api/v1/customers/**",
                "/api/v1/dentists/**","/api/v1/likes/**","/api/v1/posts/**","api/v1/services/**","/api/v1/schedule-time/**")
                .permitAll().anyRequest().authenticated();
//
        http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
        http.headers().cacheControl();
    }
}
