package com.javainuse.config;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -2550185165626007488L;
	
	public static final long JWT_TOKEN_VALIDITY = 5*60*60;

	@Value("${jwt.secret}")
	private String secret;

	public static PublicKey PUBLICKEY;
	/*
	 * @Value("${jwt.expirationDateInMs}") private int jwtExpirationInMs;
	 */
//	@Value("${jwt.refreshExpirationDateInMs}")
//	private int refreshExpirationDateInMs;
	
	private PrivateKey generateKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("EC");
		keyGenerator.initialize(new ECGenParameterSpec("secp521r1"));
		//keyGenerator.initialize(571);

		KeyPair kp = keyGenerator.genKeyPair();
		PUBLICKEY = (PublicKey) kp.getPublic();
		PrivateKey privateKey = (PrivateKey) kp.getPrivate();
		
		System.out.println("Public Key : "+PUBLICKEY);
		System.out.println("Private Key : "+privateKey);

		//String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		return privateKey;
	}

	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	/*
	 * public void setJwtExpirationInMs(int jwtExpirationInMs) {
	 * this.jwtExpirationInMs = jwtExpirationInMs; }
	 * 
	 * public void setRefreshExpirationDateInMs(int refreshExpirationDateInMs) {
	 * this.refreshExpirationDateInMs = refreshExpirationDateInMs; }
	 */
	
	public Date getIssuedAtDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getIssuedAt);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	private Boolean ignoreTokenExpiration(String token) {
		// here you specify tokens, for that the expiration is ignored
		return false;
	}

	public String generateToken(UserDetails userDetails) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		
		Map<String, Object> claims = new HashMap<>();
		

		Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();

		if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", true);
		}
		if (roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", true);
		}

		return doGenerateToken(claims, userDetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject)  throws NoSuchAlgorithmException, InvalidAlgorithmParameterException{
		PrivateKey key =  generateKeys();
		//Token valid for 180000 millis = 180 seconds
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 10)).
				signWith(SignatureAlgorithm.ES256, key).compact();
	}

	public Boolean canTokenBeRefreshed(String token) {
		return (!isTokenExpired(token) || ignoreTokenExpiration(token));
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}
