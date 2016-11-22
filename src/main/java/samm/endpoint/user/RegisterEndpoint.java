package samm.endpoint.user;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import samm.domain.user.model.User;
import samm.domain.user.service.RegisterUserOperation;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

@RestController
public class RegisterEndpoint {
    private final RegisterUserOperation registerUserOperation;

    @Inject
    public RegisterEndpoint(RegisterUserOperation registerUserOperation) {
        this.registerUserOperation = registerUserOperation;
    }

    @Transactional
    @RequestMapping(value = "/register/user", method = RequestMethod.POST)
    public ResponseEntity<?> register(@RequestBody User user, HttpServletRequest request) {
        return registerUserOperation.execute(user, request.getLocalName());
    }
}
