package com.xy.springsecuritydemo.Controller;

import com.sun.xml.internal.ws.api.server.SDDocument;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {
    /**
     * 登录
     * @return
     */
    @RequestMapping("/login")
    public String Login() {
        System.out.println("执行登录方法");
        return "redirect:Login.html";

    }

    //@Secured("ROLE_abc")
    @PreAuthorize("hasRole('abc')")
    @RequestMapping("/toMain")
    public String toMain() {
        return "redirect:Main.html";
    }

    @RequestMapping("/toError")
    public String toError() {
        return "redirect:Error.html";
    }

    @RequestMapping("/demo")
    @ResponseBody
    public String toDemo() {
        return "demo";
    }

}
