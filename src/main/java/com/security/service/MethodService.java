package com.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class MethodService {
    @Secured("ROLE_ADMIN")//���ʴ˷�����ҪADMIN��ɫ
    public String admin() {return "hello admin";}
    @PreAuthorize("hasRole('ADMIN') and hasRole('DBA')")  //���ʴ˷�����ҪADMIN��DBA
    public String dba() {
        return "hello dba";
    }
    @PreAuthorize("hasAnyRole('ADMIN','DBA','USER')")    //��������
    public String user() {
        return "hello user";
    }
}
