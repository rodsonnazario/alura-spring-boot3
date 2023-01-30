package med.voll.api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import med.voll.api.domain.usuario.Usuario;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    public String gerarToken(Usuario usuario) {
        try {
            var algoritimo = Algorithm.HMAC256("12345678");
            return JWT.create()
                    .withIssuer("API Voll.med")
                    .withSubject(usuario.getLogin())
                    .withExpiresAt(LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00")))
                    .sign(algoritimo);
        } catch (JWTCreationException exception){
            throw new RuntimeException("Erro ao gerar token jwt", exception);
        }
    }
}
