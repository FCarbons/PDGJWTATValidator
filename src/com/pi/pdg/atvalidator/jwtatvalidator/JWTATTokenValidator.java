package com.pi.pdg.atvalidator.jwtatvalidator;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

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
import com.unboundid.directory.sdk.broker.api.AccessTokenValidator;
import com.unboundid.directory.sdk.broker.config.AccessTokenValidatorConfig;
import com.unboundid.directory.sdk.broker.types.BrokerContext;
import com.unboundid.directory.sdk.broker.types.TokenValidationResult;
import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.scim2.common.GenericScimResource;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * Access Token Validator that processes JWT access tokens issued from a an
 * external IDP.
 */

public class JWTATTokenValidator extends AccessTokenValidator {

	private static final String ARG_NAME_JWKS_URL = "jwks.url";
	private static final String ARG_NAME_SUBJECT_ATTR_NAME = "subject.attrname";
	public static final String USERS_ENDPOINT = "Users";
	private static final String SCOPE_ATTR_NAME = "scope";
	private static final String CLIENT_ATTR_NAME = "client_id";

	private String subjectAttrName = "subject";
	private String jwksUrl = "";

	private BrokerContext serverContext;

	@Override
	public void initializeTokenValidator(final BrokerContext serverContext, final AccessTokenValidatorConfig config, final ArgumentParser parser)
			throws Exception {

		super.initializeTokenValidator(serverContext, config, parser);
		this.serverContext = serverContext;
		applyConfig(parser);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getExtensionName() {
		return "JWT Access Token Validator";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String[] getExtensionDescription() {
		return new String[] { "Validates JWT token (ES256 signature). Keys vor validation are downloaded from the configured JWKS endpoint" };
	}

	/**
	 * Updates the provided argument parser to define any configuration
	 * arguments which may be used by this access token validator. The argument
	 * parser may also be updated to define relationships between arguments
	 * (e.g., to specify required, exclusive, or dependent argument sets).
	 *
	 * @param parser
	 *            The argument parser to be updated with the configuration
	 *            arguments which may be used by this provider.
	 *
	 * @throws ArgumentException
	 *             If a problem is encountered while updating the provided
	 *             argument parser.
	 */
	@Override
	public void defineConfigArguments(final ArgumentParser parser) throws ArgumentException {

		Character shortIdentifier = null;
		String longIdentifier = ARG_NAME_JWKS_URL;
		boolean required = false;
		int maxOccurrences = 1;
		String placeholder = "{jwksUrl}";
		String description = "The url of the JWKS endpoint";

		parser.addArgument(new StringArgument(shortIdentifier, longIdentifier, required, maxOccurrences, placeholder, description));

		shortIdentifier = null;
		longIdentifier = ARG_NAME_SUBJECT_ATTR_NAME;
		required = false;
		maxOccurrences = 1;
		placeholder = "{subjectAttrName}";
		description = "The user attribute sent as openid claim that will be used for correlating the user in the user store.";
		parser.addArgument(new StringArgument(shortIdentifier, longIdentifier, required, maxOccurrences, placeholder, description));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public TokenValidationResult validate(final String encodedAccessToken) throws Exception {
		debug("Start TokenValidationResult " + encodedAccessToken);
		JWTClaimsSet claimsSet = validateToken(encodedAccessToken);

		debug("Token is valid");
		String subject = claimsSet.getClaims().get(subjectAttrName).toString();

		String scope = "default";
		String clientId = "deafult";

		Object scopeClaim = claimsSet.getClaims().get(SCOPE_ATTR_NAME);
		if (scopeClaim != null) {
			scope = scopeClaim.toString();
		}

		Object clientIdClaim = claimsSet.getClaims().get(CLIENT_ATTR_NAME);
		if (clientIdClaim != null) {
			clientId = clientIdClaim.toString();
		}

		debug("ClientID, subject, scope: " + clientId + "," + subject + "," + scope);
		TokenValidationResult.Builder builder = new TokenValidationResult.Builder(true);

		// convert the user name into the Broker's required format for subject
		// which is "SCIMEndpoint/SCIMId". This requires searching for the
		// user's record in the local user store.

		String filter = "username eq \"" + subject + "\"";
		ListResponse<GenericScimResource> searchResults = serverContext.getInternalScimInterface().search(USERS_ENDPOINT, filter, GenericScimResource.class);

		debug("Search complete, with number of results: " + searchResults.getTotalResults());

		if (searchResults.getTotalResults() == 0) {
			debug("User not found, returning error");
			throw new Exception("No user found that matches token name.");
		} else if (searchResults.getTotalResults() > 1) {
			debug("Multiple users found, returning error");
			throw new Exception("Found multiple users matching token user name.");
		}

		GenericScimResource localUser = searchResults.getResources().get(0);
		debug("Local user: " + localUser.getId());
		builder.setSubjectToken(USERS_ENDPOINT + "/" + localUser.getId());
		// split the string scope using the space character
		Set <String> scopeSet = new HashSet<String>(Arrays.asList (scope.split(" ")));
		debug ("Scope set: " + scopeSet);
		builder.setScope(scopeSet);
		builder.setClientId(clientId);
		TokenValidationResult tokenValidationResult = builder.build();

		debug("End TokenValidationResult " + tokenValidationResult.toString());
		return tokenValidationResult;
	}

	private JWTClaimsSet validateToken(String accessToken) throws MalformedURLException, ParseException, BadJOSEException, JOSEException {
		debug ("Start validateToken");
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
		JWKSource keySource = new RemoteJWKSet(new URL(jwksUrl));

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
		debug ("End validateToken. ClaimSet: " + claimsSet.getClaims().toString());
		return claimsSet;
	}

	private void applyConfig(final ArgumentParser parser) {
		StringArgument jwksUrlStringArg = (StringArgument) parser.getNamedArgument(ARG_NAME_JWKS_URL);
		jwksUrl = jwksUrlStringArg.getValue();
		debug("JWKS url " + jwksUrl);

		StringArgument subjectAttrNameStringArg = (StringArgument) parser.getNamedArgument(ARG_NAME_SUBJECT_ATTR_NAME);
		subjectAttrName = subjectAttrNameStringArg.getValue();
		debug("Subject attr name " + subjectAttrName);
	}

	private void debug(Object message) {
		serverContext.logMessage(LogSeverity.DEBUG, "***** " + message.toString());
		System.out.println("***** " + message.toString());
	}
	
	
	public static void main(String[] args) {
		String scope = "scopeA";
		System.out.println(Arrays.asList (scope.split(" ")));
	}
}
