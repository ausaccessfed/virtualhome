package aaf.vhr.idp;

public class BasicAuthTester {

	public static void main(String[] args) {
		String apiServer = "http://vho.dev:8080";
		String apiEndpoint = "/api/v1/login/basicauth";
		String apiToken = "bRomCePVaZMSfrCF";
		String apiSecret = "sCzxOzYznkb2YaSW";
		String requestingHost = "127.0.0.1";
		
		VhrBasicAuthValidator vhrBasicAuthValidator = new VhrBasicAuthValidator(apiServer, apiEndpoint, apiToken, apiSecret, requestingHost);

		int num = 1;
		long now = System.currentTimeMillis();
		for( int x = 0; x < num; x++) {
			vhrBasicAuthValidator.authenticate("test", "Today123");
		}
		long fin = System.currentTimeMillis();
		
		long tot = (fin-now);
		System.out.println("That took: " + tot/1000 + " seconds for " + num + " requests which is on average " + tot/num + " milliseconds per request" );
	}

}
