package cn.piao888.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @Author： hongzhi.xu
 * @Date: 2024/3/23 17:17
 * @Version 1.0
 */
@Controller
@RequiredArgsConstructor
public class PermissionController {
    @GetMapping("/no-authorization")
    @ResponseBody
    public String noAuthorization() {
        return "login";
    }

    @GetMapping("/has-read")
    @ResponseBody
    //需要显视追加SCOPE
    @PreAuthorize("hasAuthority('message.read')")
    public String hasRead() {
        return "hasRead";
    }

    @GetMapping("/has-write")
    @ResponseBody
    public String hasWrite() {
        return "hasWrite";
    }

    @GetMapping("/has-admin-role")
    //自动追加ROLE_ 变为 admin
    @PreAuthorize("hasAnyRole('admin')")
//    @PreAuthorize("hasAuthority('ROLE_admin')")
    @ResponseBody
    public String hasAdminRole() {
        return "hasAdminRole";
    }

    @GetMapping("/has-normal-role")
    @ResponseBody
    public String hasNormalRole() {
        return "hasNormalRole";
    }
}
