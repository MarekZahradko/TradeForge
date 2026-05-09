package cz.tradeforge.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        // OAuth2 Login s výchozím nastavením (Keycloak)
        http.oauth2Login(Customizer.withDefaults());

        // Logout s OIDC Logout (správné odhlášení z Keycloaku)
        http.logout((logout) -> {
            var logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");
            logout.logoutSuccessHandler(logoutSuccessHandler);
        });

        // Autorizace endpointů
        http.authorizeHttpRequests(requests -> {
            requests.requestMatchers("/api/public/**").permitAll();           // Veřejné endpointy
            requests.requestMatchers("/api/auth/register").permitAll();       // Registrace bez přihlášení
            requests.requestMatchers("/api/auth/login").permitAll();          // Login bez přihlášení
            requests.requestMatchers("/api/auth/refresh").permitAll();        // Refresh bez přihlášení
            requests.anyRequest().authenticated();                             // Všechny ostatní vyžadují přihlášení
        });

        // CORS
        http.cors(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",   // React CRA
                "http://localhost:5173"    // Vite dev server
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}