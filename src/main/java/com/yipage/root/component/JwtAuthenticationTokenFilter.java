package com.yipage.root.component;

import cn.hutool.json.JSONUtil;
import com.yipage.root.common.api.CommonResult;
import com.yipage.root.common.utils.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT登录授权过滤器
 * Created by root on 2019/5/26.
 */
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Value("${jwt.tokenHeader}")
    private String tokenHeader;
    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String requestURI = request.getRequestURI();
        String authHeader = request.getHeader(this.tokenHeader);
        if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
            String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
            String username = jwtTokenUtil.getUserNameFromToken(authToken);
            LOGGER.info("checking username:{}", username);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    LOGGER.info("authenticated user:{}", username);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } else {
                unauthorized(chain, request, response, requestURI, 2);
                return;
            }
        } else {
            unauthorized(chain, request, response, requestURI, 1);
            return;
        }
        chain.doFilter(request, response);
    }

    // 401抛出，需要手动配置过滤域名
    private void unauthorized(FilterChain chain, HttpServletRequest request, HttpServletResponse response, String requestURI, int type) throws ServletException, IOException {
        if (!requestURI.contains("/admin/login") &&
                !requestURI.contains("/admin/register") &&
                !requestURI.contains("/dictionaryValues/list") &&
                !requestURI.contains("/admin/firstLogin") &&
                !requestURI.contains("/sockjs-node/info") &&
                !requestURI.contains("/sso/getAuthCode")&&
                !requestURI.contains("/sso/verifyAuthCode")
        ) {
            // 抛出自定义异常
            try {
                response.setStatus(200);
                response.setHeader("Access-Control-Allow-Origin", "*");
                response.setCharacterEncoding("UTF-8");
                response.setContentType("application/json");
                response.getWriter().println(JSONUtil.parse(CommonResult.unauthorized(null)));
                response.getWriter().flush();
            } catch (Exception e) {
                LOGGER.error(e + "=========");
            }
        } else {
            chain.doFilter(request, response);
        }
    }
}
