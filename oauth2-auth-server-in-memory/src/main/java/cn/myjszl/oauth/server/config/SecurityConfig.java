package cn.myjszl.oauth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 *
 * 这个配置类中主要设置有4块内容
 * 1、加密方式 采用BCryptPasswordEncoder加密
 * 2、配置用户 为了方便测试，直接将用户信息存储在内存中，后续完善
 * 3、注入认证管理器AuthenticationManager AuthenticationManager在密码授权模式下会用到，这里提前注入，如果你用的不是密码模式，可以不注入
 * 4、配置安全拦截策略
 * Security 安全相关配置类
 * @author  公众号：码猿技术专栏
 * spring security的安全配置
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 加密算法
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置安全拦截策略
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //todo 允许表单登录
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .permitAll()
                .and()
                .csrf()
                .disable();
    }

    /**
     * 配置用户 了方便测试，直接将用户信息存储在内存中，后续完善
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //TODO 暂定从内存中加载用户，实际生产中需要从数据库中加载
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(new BCryptPasswordEncoder().encode("123"))
                .roles("admin")
                .and()
                .withUser("user")
                .password(new BCryptPasswordEncoder().encode("123"))
                .roles("user");
    }



    /**
     * 注入认证管理器AuthenticationManager
     * AuthenticationManager对象在OAuth2认证服务中要使用，提前放入IOC容器中
     * Oauth的密码模式需要
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}