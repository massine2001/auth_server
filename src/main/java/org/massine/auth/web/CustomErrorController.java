package org.massine.auth.web;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.WebRequest;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
public class CustomErrorController implements ErrorController {

    private final ErrorAttributes errorAttributes;

    public CustomErrorController(ErrorAttributes errorAttributes) {
        this.errorAttributes = errorAttributes;
    }

    @RequestMapping("${server.error.path:${error.path:/error}}")
    public String handleError(HttpServletRequest request, WebRequest webRequest, Model model) {
        Map<String, Object> attrs = errorAttributes.getErrorAttributes(
                webRequest,
                ErrorAttributeOptions.of(ErrorAttributeOptions.Include.MESSAGE, ErrorAttributeOptions.Include.BINDING_ERRORS)
        );

        model.addAttribute("timestamp", attrs.get("timestamp"));
        model.addAttribute("error", attrs.get("error"));
        model.addAttribute("message", attrs.getOrDefault("message", "Une erreur est survenue"));


        return "error/custom";
    }
}
