package com.nishanth.UserService.Controllers;

import com.nishanth.UserService.services.SessionService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sessions")
public class SessionController {
    private SessionService sessionService;
    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }


}
