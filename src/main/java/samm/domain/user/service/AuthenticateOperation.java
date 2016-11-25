package samm.domain.user.service;

import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import samm.domain.user.model.Credentials;
import samm.infrastructure.security.authentication.UserPrincipal;
import samm.infrastructure.security.authentication.UserAuthenticator;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import static samm.infrastructure.security.authentication.UserPrincipal.Role;

@Named
@Singleton
public class AuthenticateOperation {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateOperation.class);

    private final UserAuthenticator authenticator;

    @Inject
    public AuthenticateOperation(UserAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public Credentials execute(final String username, final String password, Role role) {
        final UserPrincipal userUserPrincipal = authenticator.authenticate(username, password, role);

        if (userUserPrincipal == null) {
            return null;
        } else {
            final Claims claims = userUserPrincipal.getClaims();
            final Credentials credentials = new Credentials();

            credentials.setAuthToken(userUserPrincipal.getAuthToken());
            credentials.setSubject(userUserPrincipal.getSubject());

            credentials.getUser().setId((String) claims.get("id"));
            credentials.getUser().setEmail((String) claims.get("email"));
            credentials.getUser().setForename((String) claims.get("forename"));
            credentials.getUser().setSurname((String) claims.get("surname"));

            return credentials;
        }
    }
}