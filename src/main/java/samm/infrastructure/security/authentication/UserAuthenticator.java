package samm.infrastructure.security.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.TextCodec;
import org.apache.commons.lang3.time.DateUtils;
import samm.dal.user.UserRepository;
import samm.domain.user.model.User;
import samm.infrastructure.security.cipher.Cipher;
import samm.infrastructure.util.RandomKeyGenerator;


import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Date;

@Named
@Singleton
public class UserAuthenticator {
    private final Cipher cipher;
    private final RandomKeyGenerator randomKeyGenerator;
    private final UserRepository userRepository;

    @Inject
    public UserAuthenticator(
                             Cipher cipher,
                             RandomKeyGenerator randomKeyGenerator,
                             UserRepository userRepository) {
        this.cipher = cipher;
        this.randomKeyGenerator = randomKeyGenerator;
        this.userRepository = userRepository;
    }

    private String getSecretKey() {
        return "JKSHBAJKSDUIQDAS";
    }

    public String generateJwtTokenForUser(final User user, Token.Type type) {
        final int validFor = type == Token.Type.PASSWORD_RESET ? 1 : 24;
        return generateJwtTokenForUser(user, validFor, type);
    }

    public String generateJwtTokenForUser(final User user, final int validFor, Token.Type type) {
        final Date issueDate = new Date();

        return Jwts.builder()
            .setId(randomKeyGenerator.generate())
            .setSubject(user.getId().toString())
            .setIssuedAt(issueDate)
            .setExpiration(DateUtils.addHours(issueDate, validFor))
            .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.encode(getSecretKey()))
            .claim(Principal.ClaimProperties.ROLE, user.getRole().toString())
            .claim(Principal.ClaimProperties.TYPE, type.toString())
            .claim(Principal.ClaimProperties.ID, user.getId().toString())
            .claim(Principal.ClaimProperties.FORENAME, user.getForename())
            .claim(Principal.ClaimProperties.SURNAME, user.getSurname())
            .claim(Principal.ClaimProperties.EMAIL, user.getEmail())
            .claim(Principal.ClaimProperties.PHONE, user.getPhone())
            .compact();
    }

    public Principal validateToken(final String token) {
        try {
            final Claims claims = Jwts.parser()
                .setSigningKey(TextCodec.BASE64.encode(getSecretKey()))
                .parseClaimsJws(token).getBody();
            return new Principal(token, Token.Status.VALID, claims);
        } catch (ExpiredJwtException expiredJwtException) {
            return new Principal(token, Token.Status.EXPIRED);
        } catch (SignatureException signatureException) {
            return new Principal(token, Token.Status.INVALID);
        }
    }

    public Claims parseToken(String token) {
        final Claims claims = Jwts.parser()
            .setSigningKey(TextCodec.BASE64.encode(getSecretKey()))
            .parseClaimsJws(token).getBody();
        return claims;
    }

    public Principal authenticate(final String username, final String plaintextPassword, final Principal.Role role) {
        final User user = userRepository.findUserByEmail(username, role);
        if (user != null && user.getActivationDate() != null) {
            if (cipher.verify(plaintextPassword, user.getPassword())) {
                return validateToken(generateJwtTokenForUser(user, Token.Type.ACCESS));
            }
        }
        return null;
    }
}

