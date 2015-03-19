/*
 * #%L
 * Conserve Concept Server
 * %%
 * Copyright (C) 2010 - 2011 KMR
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package se.kth.csc.kmr.conserve.security.oauth2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.UUID;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.CookieParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.core.Response.Status;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import javax.ws.rs.core.UriBuilder;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONTokener;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.openrdf.model.Graph;
import org.openrdf.model.ValueFactory;
import org.openrdf.model.impl.GraphImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.kth.csc.kmr.conserve.Concept;
import se.kth.csc.kmr.conserve.Contemp;
import se.kth.csc.kmr.conserve.Resolution;
import se.kth.csc.kmr.conserve.core.ConserveTerms;
import se.kth.csc.kmr.conserve.dsl.ContempDSL;
import se.kth.csc.kmr.conserve.iface.internal.RequestNotifier;
import se.kth.csc.kmr.conserve.util.TemplateManager;

@Path("/o/oauth2")
public class OAuth2Endpoints {

	private static final Logger log = LoggerFactory
			.getLogger(OAuth2Endpoints.class);

	@Inject
	@Named("conserve.session.context")
	private UUID sessionContext;

	@Inject
	@Named("conserve.user.context")
	private UUID userContext;

	@Inject
	@Named("conserve.user.predicate")
	private UUID userPredicate;

	@javax.ws.rs.core.Context
	private UriInfo uriInfo;

	@javax.ws.rs.core.Context
	private HttpServletRequest request;

	@Inject
	private Contemp store;

	@Inject
	private RequestNotifier requestNotifier;

	@Inject
	@Named("oauth")
	private TemplateManager templates;

	private static final SecureRandom RAND = new SecureRandom();

	private ContempDSL store() {
		return (ContempDSL) store;
	}

	
	
	@GET
	@Path("request")
	public Response getRequest(@QueryParam("discovery") String openIdUri,
			@QueryParam("client_id") String client_id,
			@QueryParam("client_secret") String client_secret,
			@QueryParam("return") String return_url) {
		try {


			String discoveryUri = openIdUri;

				 
				DefaultHttpClient httpClient = new DefaultHttpClient();
				
				HttpGet discovery = new HttpGet(openIdUri);
				HttpResponse response = httpClient.execute(discovery);
				int status = response.getStatusLine().getStatusCode();
				if(status>=200 && status < 300){
					Object obj = JSONValue.parse(EntityUtils.toString(response.getEntity()));
					JSONObject finalResult = (JSONObject) obj;
					UriBuilder authorizeUriBuilder = UriBuilder.fromUri(
							(String) finalResult.get("authorization_endpoint"));
					authorizeUriBuilder.queryParam("scope","openid profile email");
					authorizeUriBuilder.queryParam("client_id",client_id);
					authorizeUriBuilder.queryParam("redirect_uri",uriInfo.getBaseUri().toString()+"o/oauth2/authorize");
					authorizeUriBuilder.queryParam("response_type","code");
					if(return_url!=null){
						authorizeUriBuilder.queryParam("state",return_url);
					}
					NewCookie userinfo = new NewCookie("userinfo_endpoint",
							(String) finalResult.get("userinfo_endpoint"), "/", uriInfo.getBaseUri().getHost(),
							"Current Userinfo Endpoint", -1, false);
					NewCookie token = new NewCookie("token_endpoint",
							(String) finalResult.get("token_endpoint"), "/", uriInfo.getBaseUri().getHost(),
							"Current Token Endpoint", -1, false);
					NewCookie id = new NewCookie("client_id",
							client_id);
					NewCookie secret = new NewCookie("client_secret",
							client_secret);
					
					return Response.seeOther(authorizeUriBuilder.build()).cookie(secret).cookie(id).cookie(userinfo).cookie(token).build();
	
				}
				else{
					return Response.status(status).build();
				}
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR)
					.entity(e.getMessage()).type(MediaType.TEXT_PLAIN_TYPE)
					.build();
		} finally {
			store.disconnect();
		}
	}

	
	@GET
	@POST
	@Path("authorize")
	public Response getAccessToken(@QueryParam("code") String code,
			@QueryParam("state") String state,
			@CookieParam("token_endpoint") String tokenEP,
			@CookieParam("userinfo_endpoint") String userEP,
			@CookieParam("client_id") String clientId,
			@CookieParam("client_secret") String clientSecret){
		try{
			HttpClient client = new DefaultHttpClient();
			log.info(tokenEP);
			HttpPost post = new HttpPost(tokenEP);
			UriBuilder tokenUriBuilder = UriBuilder.fromUri (tokenEP);
			StringEntity entity = new StringEntity("grant_type=authorization_code&client_id="+clientId+"&client_secret="+clientSecret+"&code="+code+"&redirect_uri="+uriInfo.getBaseUri().toString()+"o/oauth2/authorize"); //+uriInfo.getBaseUri().toString()+"o/oauth2/authenticate");
			post.setEntity(entity);
			post.setHeader("Content-Type","application/x-www-form-urlencoded");
			HttpResponse response = client.execute(post);
			Object obj = JSONValue.parse(EntityUtils.toString(response.getEntity()));
			JSONObject tokenResult = (JSONObject) obj;
			String accessToken = (String) tokenResult.get("access_token");
			HttpGet userinfoRequest = new HttpGet(userEP);
			userinfoRequest.setHeader("Authorization", "Bearer " + accessToken);
			HttpResponse userinfoResponse;
			userinfoResponse = client.execute(userinfoRequest);
			Object userinfoObj = JSONValue.parse(EntityUtils.toString(userinfoResponse.getEntity()));
			JSONObject finalResult = (JSONObject) userinfoObj;
			String firstName = (String) finalResult.get("given_name");
			String lastName = (String) finalResult.get("family_name");
			String email = (String) finalResult.get("email");
			String userName = "mailto:" + email;

			Concept user = store().in(userContext).sub().get(userName);
			if (user == null) {
				user = store().in(userContext).sub(userPredicate)
						.create(userName);

				Graph graph = new GraphImpl();
				ValueFactory valueFactory = graph.getValueFactory();
				org.openrdf.model.URI userUri = valueFactory
						.createURI(store().in(user).uri().toString());
				graph.add(valueFactory.createStatement(
						userUri,
						valueFactory
								.createURI("http://purl.org/dc/terms/title"),
						valueFactory.createLiteral(firstName + " "
								+ lastName)));
				// email
				graph.add(valueFactory.createStatement(
						userUri,
						valueFactory
								.createURI("http://xmlns.com/foaf/0.1/mbox"),
						valueFactory.createURI("mailto:" + email)));
				// access_token
				graph.add(valueFactory.createStatement(
						userUri,
						valueFactory
								.createURI("http://xmlns.com/foaf/0.1/openid"),
						valueFactory.createLiteral(accessToken)));
				store().in(user).as(ConserveTerms.metadata)
						.type("application/json").graph(graph);
				requestNotifier.setResolution(
						Resolution.StandardType.CONTEXT,
						store.getConcept(userContext));
				requestNotifier.setResolution(
						Resolution.StandardType.CREATED, user);
				requestNotifier.doPost();

			}
			Concept session = store().in(sessionContext).sub()
					.create(randomString());
			store().in(session)
					.put(ConserveTerms.reference, user.getUuid());

			NewCookie cookie = new NewCookie("conserve_session",
					session.getId(), "/", uriInfo.getBaseUri().getHost(),
					"conserve session id", 1200000, false);
			NewCookie userinfo = new NewCookie("userinfo_endpoint",
					(String) finalResult.get("userinfo_endpoint"), "/", uriInfo.getBaseUri().getHost(),
					"Current Userinfo Endpoint", 0, false);
			NewCookie token = new NewCookie("token_endpoint",
					(String) finalResult.get("token_endpoint"), "/", uriInfo.getBaseUri().getHost(),
					"Current Token Endpoint", 0, false);
			NewCookie id = new NewCookie("client_id",
					"","/",uriInfo.getBaseUri().getHost(),"",0,false);
			NewCookie secret = new NewCookie("client_secret",
					"","/",uriInfo.getBaseUri().getHost(),"",0,false);
			
			UriBuilder spacereturn = UriBuilder.fromUri(uriInfo.getBaseUri().toString());
			if(state != null){
				spacereturn.path(state);
			}
			return Response.seeOther(spacereturn.build()).cookie(cookie)
					.header("Cache-Control", "no-store").build();
		}
		catch(Exception e){
			return Response.status(Status.INTERNAL_SERVER_ERROR)
					.entity(e.getMessage()).type(MediaType.TEXT_PLAIN_TYPE)
					.build();
		}
		finally{
			store.disconnect();
		}
	}

	private static String randomString() {
		byte[] secret = new byte[16];
		RAND.nextBytes(secret);
		return Base64.encodeBase64URLSafeString(secret);
	}

}
