package com.pi.pdg.atvalidator.jwtatvalidator;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class JWKSTest {

	public static void main(String[] args) throws Exception {
		String accessToken = "eyJraWQiOiIxYSIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJQaW5nQWNjZXNzQXV0aFRva2VuIiwic3ViIjoiZmVkZSIsImF1ZCI6Ik15Q3VzdG9tQXVkaWVuY2UiLCJleHAiOjE0ODU5OTA3MDcsImlhdCI6MTQ4NTk4NzA5N30.rPTL0VZbQQIpWx_4rW2Y8XnnC0KSJN0659JgErCelpiqePBULRmdLpFxujBNQ45JcIKBzWuUiukKEOJ_BvPGtw";

		JWTClaimsSet claimsSet = validateToken(accessToken);

		// Print out the token claims set
		System.out.println(claimsSet.toJSONObject());
	}

	private static JWTClaimsSet validateToken(String accessToken) throws MalformedURLException, ParseException, BadJOSEException, JOSEException {
		// Set up a JWT processor to parse the tokens and then check their
		// signature
		// and validity time window (bounded by the "iat", "nbf" and "exp"
		// claims)
		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

		// The public RSA keys to validate the signatures will be sourced from
		// the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The
		// RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and
		// can
		// also gracefully handle key-rollover
		JWKSource keySource = new RemoteJWKSet(new URL("http://localhost:8099/pa/authtoken/JWKS"));

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.ES256;

		// Configure the JWT processor with a key selector to feed matching
		// public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required
									// here
		JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);
		return claimsSet;
	}

}
