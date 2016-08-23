package aaf.vhr.idp.http;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.net.URLCodec;
import org.opensaml.util.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

import aaf.vhr.idp.VhrSessionValidator;

public class VhrFilter implements Filter {
	
	final String SSO_COOKIE_NAME = "_vh_l1";
	
	private String vhrLoginEndpoint;
	private VhrSessionValidator vhrSessionValidator;
	
	Logger log = LoggerFactory.getLogger("aaf.vhr.idp.http.VhrFilter");
			
	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res,
			FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		if(request.getRemoteUser() != null) {
			log.info("Found REMOTE_USER of {} was already set by previous filter or webserver module. Disabling VHR authentication process.", req.getRemoteHost());
			chain.doFilter(request, response);
			return;
		}
		
		URLCodec codec = new URLCodec();
		StorageService storageService = HttpServletHelper.getStorageService(req.getServletContext());
		LoginContext loginContext = HttpServletHelper.getLoginContext(storageService, req.getServletContext(), request);
		String relyingParty = loginContext.getRelyingPartyId();
		
		// Attempt to locate VHR SessionID
		String vhrSessionID = null;
		Cookie[] cookies = request.getCookies();
		for(Cookie cookie : cookies) {
			if(cookie.getName().equals(SSO_COOKIE_NAME)) {
				vhrSessionID = cookie.getValue();
				break;
			}
		}
		
		if(vhrSessionID == null) {
			log.info("No vhrSessionID found from {}. Directing to VHR authentication process.", req.getRemoteHost());
			log.debug ("Relying party which initiated the SSO request was: {}", relyingParty);
			
			try {
				response.sendRedirect(String.format(vhrLoginEndpoint, codec.encode(request.getRequestURL().toString()), codec.encode(relyingParty)));
			} catch (EncoderException e) {
				log.error ("Could not encode VHR redirect params");
				throw new IOException(e);
			}
			return;
		}
		
		log.info("Found vhrSessionID from {}. Establishing validity.", req.getRemoteHost());
		String remoteUser = vhrSessionValidator.validateSession(vhrSessionID);
		
		if(remoteUser != null) {
			log.info("Established validity for {}, setting REMOTE_USER to {}", req.getRemoteHost(), remoteUser);
			
			VhrRequestWrapper vhrRequestWrapper = new VhrRequestWrapper(request, remoteUser);
			
			chain.doFilter(vhrRequestWrapper, response);
			return;
		}
		
		try {
			log.info("Failed to establish validity for {} vhrSessionID.", req.getRemoteHost());
			response.sendRedirect(String.format(vhrLoginEndpoint, codec.encode(request.getRequestURL().toString()), codec.encode(relyingParty)));
		} catch (EncoderException e) {
			log.error ("Could not encode VHR redirect params after failing to establish validity");
			throw new IOException(e);
		}
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		vhrLoginEndpoint = filterConfig.getInitParameter("loginEndpoint");
		String apiServer = filterConfig.getInitParameter("apiServer");
		String apiEndpoint = filterConfig.getInitParameter("apiEndpoint");
		String apiToken = filterConfig.getInitParameter("apiToken");
		String apiSecret = filterConfig.getInitParameter("apiSecret");
		String requestingHost = filterConfig.getInitParameter("requestingHost");
		
		vhrSessionValidator = new VhrSessionValidator(apiServer, apiEndpoint, apiToken, apiSecret, requestingHost);
	}

}
