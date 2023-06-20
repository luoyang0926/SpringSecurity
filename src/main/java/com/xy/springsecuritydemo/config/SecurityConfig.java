package com.xy.springsecuritydemo.config;

import com.xy.springsecuritydemo.handler.MyAuthenticationFailureHandler;
import com.xy.springsecuritydemo.handler.MyAuthenticationSuccessHandler;
import com.xy.springsecuritydemo.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

    /**
     * 配置类
     */
    @Bean
    public PasswordEncoder getPw() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public PersistentTokenRepository getPT() {
        JdbcTokenRepositoryImpl jdbcTokenRepository=new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //自动建表，第一次启动时候需要，第二次启动注释掉
       // jdbcTokenRepository.setCreateTableOnStartup(true);
        return  jdbcTokenRepository;

    }

    @Override
    protected void configure(HttpSecurity http)throws Exception {
        //表单提交
        http.formLogin()
                .loginProcessingUrl("/login")
                //自定义的登录页面
                .loginPage("/Login.html")
                //登录成功之后，必须为Post请求
                 .successForwardUrl("/toMain")
                //.successHandler(new MyAuthenticationSuccessHandler("http://www.baidu.com"))
                //登录失败跳转页面
                .failureForwardUrl("/toError");
                //.failureHandler(new MyAuthenticationFailureHandler("http://www.jd.com"));

        //授权认证
        http.authorizeRequests()
                .antMatchers("/Error.html").permitAll()
                //所有请求都必须被认证，必须登录之后被访问
                .antMatchers("/Login.html").permitAll()
                //.mvcMatchers("/demo").servletPath("/qz").permitAll()
                // .mvcMatchers("/main1.html").hasAnyAuthority("admin")
                //.antMatchers("/main1.html").hasRole("abc")
                .anyRequest().authenticated();

        http.rememberMe()
                .tokenValiditySeconds(60)
                //自定义登录逻辑
                .userDetailsService(userDetailsService)
                //持久层对象
                .tokenRepository(persistentTokenRepository);
        //退出登录
        http.logout()
                .logoutSuccessUrl("/login");

        //关闭csrf防火墙
        http.csrf().disable();
    }
}
