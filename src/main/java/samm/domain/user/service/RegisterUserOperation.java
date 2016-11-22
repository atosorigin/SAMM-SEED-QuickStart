package samm.domain.user.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import samm.dal.user.UserRepository;
import samm.dal.user.WhiteListRepository;
import samm.domain.user.model.User;
import samm.infrastructure.mail.EmailService;
import samm.infrastructure.security.authentication.Token;
import samm.infrastructure.security.authentication.UserAuthenticator;
import samm.infrastructure.security.cipher.BCryptCipher;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import static samm.infrastructure.security.authentication.Principal.Role;

@Named
@Singleton
public class RegisterUserOperation {
    private static final Logger LOG = LoggerFactory.getLogger(RegisterUserOperation.class);

    private final UserRepository repository;
    private final BCryptCipher cipher;
    private final EmailService emailService;
    private final UserAuthenticator authenticator;
    private final WhiteListRepository whiteListRepository;
    private final TemplateEngine templateEngine;

    @Inject
    public RegisterUserOperation(UserRepository repository,
                                 BCryptCipher cipher,
                                 UserAuthenticator authenticator,
                                 EmailService emailService,
                                 WhiteListRepository whiteListRepository,
                                 TemplateEngine templateEngine) {
        this.repository = repository;
        this.cipher = cipher;
        this.emailService = emailService;
        this.authenticator = authenticator;
        this.whiteListRepository = whiteListRepository;
        this.templateEngine = templateEngine;
    }

    public ResponseEntity<?> execute(User user, String baseUrl) {
        if (user.getActivationDate() != null) {
            LOG.info("Attempted activation with Registration: " + user.getEmail());
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }

        if (!whiteListRepository.emailWhiteListed(user.getEmail(), Role.USER)) {
            return new ResponseEntity<>("You're not authorised to use this application", HttpStatus.FORBIDDEN);
        }

        final User existingUser = repository.findUserByEmail(user.getEmail(), Role.USER);
        if (existingUser != null) {
            LOG.info("Registration attempted with existing: " + user.getEmail());
            return new ResponseEntity<>("Account Exists", HttpStatus.CONFLICT);
        }

        user.setRole(Role.USER);
        user.setPassword(cipher.hash(user.getPassword()));
        repository.set(user);

        final Context context = new Context();
        context.setVariable("user", user.getForename());
        context.setVariable("baseUrl", baseUrl);
        context.setVariable("token", authenticator.generateJwtTokenForUser(user, Token.Type.ACTIVATE));

        emailService.sendEmail(user.getEmail(),
            "Welcome to Atos SAMM Portal. Please activate your account",
            templateEngine.process("userActivation", context));

        return new ResponseEntity<>(HttpStatus.OK);
    }
}
