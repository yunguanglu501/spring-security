package cn.myjszl.security.jwt.filter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 自定义登录过滤器
 * @author 公众号：码猿技术专栏
 * 默认的过滤器是UsernamePasswordAuthenticationFilter,登录认证的filter，
 * 参照UsernamePasswordAuthenticationFilter，添加到这之前的过滤器
 * 定义了一个认证过滤器JwtAuthenticationLoginFilter，这个是用来登录的过滤器，
 * 但是并没有注入加入Spring Security的过滤器链中，需要定义配置
 */
public class JwtAuthenticationLoginFilter extends AbstractAuthenticationProcessingFilter {

    /**
     * 构造方法，调用父类的，设置登录地址/login，请求方式POST
     */
    public JwtAuthenticationLoginFilter() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        //获取表单提交数据
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        //封装到token中提交
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                username,password);
        return getAuthenticationManager().authenticate(authRequest);

    }
}
