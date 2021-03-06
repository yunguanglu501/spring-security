package cn.myjszl.common.base.service.impl;

import cn.myjszl.common.base.model.SecurityUser;
import cn.myjszl.common.base.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 *
 * 在认证逻辑中Spring Security会调用这个方法根据客户端传入的username加载该用户的详细信息，这个方法需要完成的逻辑如下：
 * 密码匹配
 * 加载权限、角色集合
 * @author 公众号：码猿技术专栏
 * 从数据库中根据用户名查询用户的详细信息，包括权限
 * 这个类是用来加载用户信息，包括用户名、密码、权限、角色集合....其中有一个方法如下：
 * 数据库设计：角色、用户、权限、角色<->权限、用户<->角色 总共五张表，遵循RBAC设计
 */
@Service
public class JwtTokenUserDetailsService implements UserDetailsService {

    /**
     * 查询用户详情的service
     */
    @Autowired
    private LoginService loginService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //从数据库中查询
        SecurityUser securityUser = loginService.loadByUsername(username);
        //用户不存在直接抛出UsernameNotFoundException，security会捕获抛出BadCredentialsException
        if (Objects.isNull(securityUser))
            throw new UsernameNotFoundException("用户不存在！");
        return securityUser;
    }
}
