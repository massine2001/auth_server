package org.massine.auth.web;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String loginUrl, Model model) {
        model.addAttribute("loginUrl", loginUrl);
        return "login";
    }
}
