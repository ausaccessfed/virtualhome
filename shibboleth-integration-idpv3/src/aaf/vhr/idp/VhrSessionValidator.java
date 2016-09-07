package aaf.vhr.idp;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VhrSessionValidator {
	private final String DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss z";
	private final String AUTHORIZE_HEADER = "AAF-HMAC-SHA256 token=\"%s\", signature=\"%s\"";
	
	Logger log = LoggerFactory.getLogger("aaf.vhr.idp.VhrSessionValidator");
	
	private String apiServer;
	private String apiEndpoint;
	private String apiToken;
	private String apiSecret;
	private String requestingHost;
	
	public VhrSessionValidator(String apiServer, String apiEndpoint, String apiToken, String apiSecret, String requestingHost) {
		this.apiServer = apiServer;
		this.apiEndpoint = apiEndpoint;
		this.apiToken = apiToken;
		this.apiSecret = apiSecret;
		this.requestingHost = requestingHost;
	}
	
	public String validateSession(String vhrSessionID) {
		return validateSession(vhrSessionID, null, null);
	}

	public String validateSession(String vhrSessionID, DateTime notBefore, DateTime authnInstantArr[]) {
		HttpClient httpClient = null;
		HttpGet request = null;
		HttpResponse response = null;
		
		try {
			log.info("Contacting VHR API for sessionID {} details", vhrSessionID); 
			
			String requestPath = String.format(this.apiEndpoint, vhrSessionID);
			
			Date requestDate = new Date();
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
			String requestDateHeader = sdf.format(requestDate);
			
			String requestSignature = calculateSecret(requestPath, requestDateHeader);
			String requestAuthorizeHeader = String.format(AUTHORIZE_HEADER, this.apiToken, requestSignature);
			
			URIBuilder builder = new URIBuilder(new URI(this.apiServer));
			builder.setPath(requestPath);
			request = new HttpGet(builder.build());
			
			// Format our request to communicate with AAF API
			request.setHeader("Date", requestDateHeader);
			request.setHeader("Authorization", requestAuthorizeHeader);
			
			log.info("Create complete VHR API request with the following details:");
			log.info("Date: " + requestDateHeader);
			log.info("Authorization: " + requestAuthorizeHeader);
			log.info("Request: " + request);

			httpClient = new DefaultHttpClient();
			response = httpClient.execute(request);
			
			log.info("Response status: {}", response.getStatusLine().getStatusCode());
			if(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK){
				JSONObject responseJSON = parseJSON(response.getEntity());
				if(responseJSON != null) {
					String remoteUser = (String) responseJSON.get("remote_user");
					String authnInstant = (String) responseJSON.get("authnInstant");
					DateTime jtAuthnInstant = null;
					if (authnInstant != null) {
					    log.debug("VHR response includes an AuthnInstant: {}", authnInstant);
					    jtAuthnInstant = new DateTime(authnInstant, ISOChronology.getInstanceUTC());
					    log.debug("VHR response authnInstant as org.joda.time.DateTime is: {}", jtAuthnInstant);
					}
					// if notBefore was requested and we are either missing jtAuthnInstant or jtAuthnInstant was *before* notBefore, reject the session
					if (notBefore != null && (jtAuthnInstant == null || jtAuthnInstant.compareTo(notBefore) < 0)) {
					    log.info("Rejecting username {} as authnInstant {} is earlier than the notBefore threshold {}", remoteUser, jtAuthnInstant, notBefore);
					    remoteUser = null;
					};
					
					if(remoteUser != null) {
						log.info("VHR API advises sessionID {} belongs to user {}, setting for REMOTE_USER.", vhrSessionID, remoteUser);
						if (jtAuthnInstant != null && authnInstantArr != null && authnInstantArr.length>=1) {
							log.info("VHR API sets authnInstant to {}.", jtAuthnInstant);
							authnInstantArr[0]=jtAuthnInstant;
						};
						return remoteUser;
					}
				}
            } else {
            	log.error("VHR API error for sessionID {}",vhrSessionID); 
            	JSONObject responseJSON = parseJSON(response.getEntity());
				if(responseJSON != null) {
					String error = (String) responseJSON.get("error");
					String internalerror = (String) responseJSON.get("internalerror");
					log.error("VHR API Error: {}", error);
					log.error("VHR API Internal Error: {}", internalerror);
				} else {
					log.error("VHR API error with no JSON error detail provided.");
				}
				request.abort();
            }
		} catch (Exception e) {
			log.error("Exception casued when ontacting VHR API for sessionID {} details.\nMessage: {}", vhrSessionID, e.getMessage());
			e.printStackTrace();
		} finally {
			if(request != null)
				request.reset();
		}
		
		return null;
	}
	
	private JSONObject parseJSON(HttpEntity entity) throws ParseException, org.apache.http.ParseException, IOException {
		ContentType contentType = ContentType.getOrDefault(entity);
		if(contentType.getMimeType().equals(ContentType.APPLICATION_JSON.getMimeType())) {
			String responseJSON = EntityUtils.toString(entity); 
	
			JSONParser parser = new JSONParser();
			Object obj = parser.parse(responseJSON);
			return (JSONObject) obj;
		}
		return null;
	}
	
	private String calculateSecret(String requestPath, String requestDateHeader) throws NoSuchAlgorithmException, InvalidKeyException {
		StringBuffer input = new StringBuffer();
	    input.append("get\n");
	    input.append(String.format("%s\n", this.requestingHost.toLowerCase()));
	    input.append(String.format("%s\n", requestPath.toLowerCase()));
	    input.append(String.format("%s\n", requestDateHeader.toLowerCase()));
	    
	    log.debug("Creating request signature from following input:\n{}", input.toString());
	    
	    SecretKeySpec signingKey = new SecretKeySpec(apiSecret.getBytes(), "HmacSHA256");
	    Mac mac = Mac.getInstance("HmacSHA256");
	    mac.init(signingKey);
	    byte[] rawHmac = mac.doFinal(input.toString().getBytes());
	    
		return new String(Base64.encodeBase64(rawHmac));
	}
}
