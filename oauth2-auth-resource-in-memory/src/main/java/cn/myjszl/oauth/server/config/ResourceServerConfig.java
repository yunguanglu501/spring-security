package cn.myjszl.oauth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

/**
 * 客户端申请令牌的目的就是为了访问资源，当然这个资源也是分权限的，一个令牌不是所有资源都能访问的。
 * 在认证中心搭建的第6步配置客户端详情的时候，一行代码.resourceIds("res1")则指定了能够访问的资源，
 * 可以配置多个，这里的res1则是唯一对应一个资源。
 * @author 公众号：码猿技术专栏
 * OAuth2.0 资源服务的配置类
 * `@EnableResourceServer`：该注解标记这是一个资源服务
 * `@EnableGlobalMethodSecurity`：该注解开启注解校验权限
 */
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true,jsr250Enabled = true,securedEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    /**
     * 由于认证中心使用的令牌存储策略是在内存中的，因此服务端必须远程调用认证中心的校验令牌端点/oauth/check_token**进行校验。
     * 配置令牌校验服务，客户端携带令牌访问资源，作为资源端必须检验令牌的真伪
     * 注意：远程校验令牌存在性能问题，但是后续使用JWT令牌则本地即可进行校验，不必远程校验了。
     * TODO 使用JWT作为TOKEN则不必远程调用check_token校验
     * ResourceServerTokenServices 接口定义了令牌加载、读取方法
     */
    @Bean
    public RemoteTokenServices tokenServices() {
        //远程调用授权服务的check_token进行令牌的校验
        RemoteTokenServices services = new RemoteTokenServices();
        // /oauth/check_token 这个url是认证中心校验的token的端点
        services.setCheckTokenEndpointUrl("http://localhost:2003/auth-server/oauth/check_token");
        //客户端的唯一id
        services.setClientId("myjszl");
        //客户端的秘钥
        services.setClientSecret("123");
        return services;
    }

    /**
     * 配置资源id和令牌校验服务
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources)  {
        //配置唯一资源id
        resources.resourceId("res1")
                //配置令牌校验服务
                .tokenServices(tokenServices());
    }

    /**
     * 配置security的安全机制
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        //#oauth2.hasScope()校验客户端的权限，这个all是在客户端中的scope
        http.authorizeRequests()
                .antMatchers("/**").access("#oauth2.hasScope('all')")
                .anyRequest().authenticated();
    }
}