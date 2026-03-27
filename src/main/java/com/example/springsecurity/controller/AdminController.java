package com.example.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody // 해당 컨트롤러는 api 서버로 동작할 것이기 때문에,웹 페이지가 아닌 특정 문자열 데이터를 응답하도록 해준다.
public class AdminController {

    @GetMapping("/admin")
    public String adminP() {
        return "admin Controller";
    }

}
