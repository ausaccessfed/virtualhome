package aaf.vhr.idp.http;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class VhrRequestWrapper extends HttpServletRequestWrapper {

	String remoteUser;
	
	public VhrRequestWrapper(HttpServletRequest request, String remoteUser) {
		super(request);
		this.remoteUser = remoteUser;
	}

	@Override
	public String getRemoteUser() {
		return remoteUser;
	}

	
}
