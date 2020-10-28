package com.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.filter.JwtAuthenticationTokenFilter;
import com.security.service.UserService;
import com.security.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
//prePostEnabled=true�����@PreAuthorize��@PostAuthorize����ע��
// ����˼�壬@PreAuthorizeע����ڷ���ִ��ǰ������֤����@PostAuthorize ע���ڷ���ִ�к������֤��
//securedEnabled=true�����@Securedע�⡣
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserService userService;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtTokenUtil jwtTokenUtil() {
        return new JwtTokenUtil();
    }

    @Bean
    public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter() {
        return new JwtAuthenticationTokenFilter();
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll()  //urlΪ/login�����
                .antMatchers("/admin/**")
                .hasRole("ADMIN")   //urlΪ/admin/����Ҫadmin��ɫ��/user/����Ҫadmin����user��/db/����Ҫadmin��dba��ɫ
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                .antMatchers("/db/**")
                .access("hasAnyRole('ADMIN') and  hasRole('DBA')")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().permitAll()//��½ҳ�����
                .loginPage("/login.html") //�Զ����½ҳ��
                .loginProcessingUrl("/mylogin")//�Զ����½ҳ��ĵ�½action

                .successHandler(new AuthenticationSuccessHandler() {//��½�ɹ���
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        Authentication auth)
                            throws IOException {
                        Object principal = auth.getPrincipal();
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(200);
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", principal);
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })

                .failureHandler(new AuthenticationFailureHandler() {//��½ʧ�ܺ�
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        AuthenticationException e)
                            throws IOException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(401);
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 401);
                        if (e instanceof LockedException) {
                            map.put("msg", "�˻�����������¼ʧ��!");
                        } else if (e instanceof BadCredentialsException) {
                            map.put("msg", "�˻���������������󣬵�¼ʧ��!");
                        } else if (e instanceof DisabledException) {
                            map.put("msg", "�˻������ã���¼ʧ��!");
                        } else if (e instanceof AccountExpiredException) {
                            map.put("msg", "�˻��ѹ��ڣ���¼ʧ��!");
                        } else if (e instanceof CredentialsExpiredException) {
                            map.put("msg", "�����ѹ��ڣ���¼ʧ��!");
                        } else {
                            map.put("msg", "��¼ʧ��!");
                        }
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .and()

                .logout()//����ע����½
                .logoutUrl("/logout")//ע����½����url
                .clearAuthentication(true)//��������Ϣ
                .invalidateHttpSession(true)//sessionʧЧ
                .addLogoutHandler(new LogoutHandler() {//ע������
                    @Override
                    public void logout(HttpServletRequest req,
                                       HttpServletResponse resp,
                                       Authentication auth) {

                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { //ע���ɹ�����
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req,
                                                HttpServletResponse resp,
                                                Authentication auth)
                            throws IOException {
                        resp.sendRedirect("/login.html");//��ת���Զ����½ҳ��
                    }
                })
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//ǰ��˷������JWT ����Ҫsession
                .and()
                .addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}
