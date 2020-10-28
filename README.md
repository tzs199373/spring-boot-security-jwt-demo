# SpringSecurity整合JWT

本项目是在spring-boot-security-demo-v2基础上稍加改造，数据库脚本参考spring-boot-security-demo-v2，对JWT不了解的建议先了解一下JWT

# JWT核心

JwtTokenUtil用于生成与解析JWT

JwtAuthenticationTokenFilter用于从过滤请求，提取JWT并认证

# 登陆

入口在HelloController.login

# WebSecurityConfig改造

MyWebSecurityConfig中虽然沿用spring-boot-security-demo-v2保留了登陆页面，但JWT不用这个页面测试，JWT主要用于前后端分离项目，还是使用HelloController.login登陆。需要开放login

```java
http.authorizeRequests()
                .antMatchers("/login").permitAll()  //url为/login则放行
```

然后config方法中需要添加如下配置

```java
//链式调用，前面代码省略
.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//前后端分离采用JWT 不需要session
                .and()
                .addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
```

