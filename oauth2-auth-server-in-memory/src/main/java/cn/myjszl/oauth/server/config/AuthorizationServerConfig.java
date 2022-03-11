package cn.myjszl.oauth.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author  公众号：码猿技术专栏
 * 认证中心的配置
 * `@EnableAuthorizationServer`：这个注解标注这是一个认证中心
 * 继承AuthorizationServerConfigurerAdapter
 */
@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * 令牌存储策略
     */
    @Autowired
    private TokenStore tokenStore;

    /**
     * 客户端存储策略，这里使用内存方式，后续可以存储在数据库
     */
    @Autowired
    private ClientDetailsService clientDetailsService;

    /**
     * Security的认证管理器，密码模式需要用到
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 配置客户端详情，并不是所有的客户端都能接入授权服务
     * OAuth2.0 协议的时候介绍到，并不是所有的客户端都有权限向认证中心申请令牌的，首先认证中心要知道你是谁，你有什么资格？
     * 因此一些必要的配置是要认证中心分配给你的，比如客户端唯一Id、秘钥、权限。
     * 客户端配置的存储也支持多种方式，比如内存、数据库，
     * 对应的接口为：org.springframework.security.oauth2.provider.ClientDetailsService
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //TODO 暂定内存模式，后续可以存储在数据库中，更加方便
        clients.inMemory()
                //客户端id
                .withClient("myjszl")
                //客户端秘钥
                .secret(new BCryptPasswordEncoder().encode("123"))
                //资源id，唯一，比如订单服务作为一个资源,可以设置多个
                .resourceIds("res1")
                //授权模式，总共四种，1. authorization_code（授权码模式）、password（密码模式）、client_credentials（客户端模式）、implicit（简化模式）
                //refresh_token并不是授权模式，
                .authorizedGrantTypes("authorization_code","password","client_credentials","implicit","refresh_token")
                //允许的授权范围，客户端的权限，这里的all只是一种标识，可以自定义，为了后续的资源服务进行权限控制
                .scopes("all")
                //false 则跳转到授权页面
                //autoApprove：是否需要授权，设置为true则不需要用户点击确认授权直接返回授权码
                .autoApprove(false)
                //授权码模式的回调地址
                .redirectUris("http://www.baidu.com");
    }

    /**
     * 令牌管理服务的配置
     * 除了令牌的存储策略需要配置，还需要配置令牌的服务AuthorizationServerTokenServices用来创建、获取、刷新令牌，代码如下：
     */
    @Bean
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        //客户端端配置策略
        services.setClientDetailsService(clientDetailsService);
        //支持令牌的刷新
        services.setSupportRefreshToken(true);
        //令牌服务
        services.setTokenStore(tokenStore);
        //access_token的过期时间
        services.setAccessTokenValiditySeconds(60 * 60 * 2);
        //refresh_token的过期时间
        services.setRefreshTokenValiditySeconds(60 * 60 * 24 * 3);
        return services;
    }


    /**
     * 授权码模式的service，使用授权码模式authorization_code必须注入
     * 使用授权码模式必须配置一个授权码服务，用来颁布和删除授权码，当然授权码也支持多种方式存储，比如内存，数据库，这里暂时使用内存方式存储
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        //todo 授权码暂时存在内存中，后续可以存储在数据库中
        return new InMemoryAuthorizationCodeServices();
    }

    /**
     * 配置令牌访问的端点
     * 目前这里仅仅配置了四个，分别如下：
     * 配置了授权码模式所需要的服务，AuthorizationCodeServices
     * 配置了密码模式所需要的AuthenticationManager
     * 配置了令牌管理服务，AuthorizationServerTokenServices
     * 配置/oauth/token申请令牌的uri只允许POST提交。
     * spring Security框架默认的访问端点有如下6个：
     * /oauth/authorize：获取授权码的端点
     * /oauth/token：获取令牌端点。
     * /oauth/confifirm_access：用户确认授权提交端点。
     * /oauth/error：授权服务错误信息端点。
     * /oauth/check_token：用于资源服务访问的令牌解析端点。
     * /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话。
     * 当然如果业务要求需要改变这些默认的端点的url，也是可以修改的，AuthorizationServerEndpointsConfigurer有一个方法，如下：
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                //授权码模式所需要的authorizationCodeServices
                .authorizationCodeServices(authorizationCodeServices())
                //密码模式所需要的authenticationManager
                .authenticationManager(authenticationManager)
                //令牌管理服务，无论哪种模式都需要
                .tokenServices(tokenServices())
                //只允许POST提交访问令牌，uri：/oauth/token
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    /**
     * 配置令牌访问的安全约束
     * 主要对一些端点的权限进行配置，代码如下：
     * 令牌端点约束配置,比如/oauth/token对哪些开放
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                //开启/oauth/token_key验证端口权限访问
                .tokenKeyAccess("permitAll()")
                //开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("permitAll()")
                //表示支持 client_id 和 client_secret 做登录认证
                .allowFormAuthenticationForClients();
    }





}