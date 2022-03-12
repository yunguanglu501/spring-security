package cn.myjszl.security.jwt.filter;

import cn.myjszl.common.base.constant.SecurityConstant;
import cn.myjszl.common.base.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * 客户端请求头携带了token，服务端肯定是需要针对每次请求解析、校验token，因此必须定义一个Token过滤器，这个过滤器的主要逻辑如下：
 * 从请求头中获取accessToken
 * 对accessToken解析、验签、校验过期时间
 * 校验成功，将authentication存入ThreadLocal中，这样方便后续直接获取用户详细信息。
 * @author 公众号：码猿技术专栏
 * 校验token的过滤器，直接获取header中的token进行校验，
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    /**
     * JWT的工具类
     */
    @Autowired
    private JwtUtils jwtUtils;

    /**
     * UserDetailsService的实现类，从数据库中加载用户详细信息
     */
    @Qualifier("jwtTokenUserDetailsService")
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = request.getHeader(SecurityConstant.TOKEN_HEADER);
        /**
         * token存在则校验token
         * 1. token是否存在
         * 2. token存在：
         *  2.1 校验token中的用户名是否失效
         */
        if (!StringUtils.isEmpty(token)){
            String username = jwtUtils.getUsernameFromToken(token);
            //SecurityContextHolder.getContext().getAuthentication()==null 未认证则为true
            if (!StringUtils.isEmpty(username) && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                //如果token有效
                if (jwtUtils.validateToken(token,userDetails)){
                    // 将用户信息存入 authentication，方便后续校验
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                            userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // 将 authentication 存入 ThreadLocal，方便后续获取用户信息
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        //继续执行下一个过滤器
        chain.doFilter(request,response);
    }
}
