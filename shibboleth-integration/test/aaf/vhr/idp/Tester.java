package aaf.vhr.idp;

public class Tester {

	public static void main(String[] args) {
		String apiServer = "http://brainslave.dev.bradleybeddoes.com:8181";
		String apiEndpoint = "/virtualhome/api/v1/login/confirmsession/%s";
		String apiToken = "bRomCePVaZMSfrCF";
		String apiSecret = "sCzxOzYznkb2YaSW";
		String requestingHost = "192.168.56.1";
		
		VhrSessionValidator vhrSessionValidator = new VhrSessionValidator(apiServer, apiEndpoint, apiToken, apiSecret, requestingHost);

		int num = 500;
		long now = System.currentTimeMillis();
		for( int x = 0; x < num; x++) {
			//System.out.println(vhrSessionValidator.validateSession("1234"));
			vhrSessionValidator.validateSession("1234");
		}
		long fin = System.currentTimeMillis();
		
		long tot = (fin-now);
		System.out.println("That took: " + tot/1000 + " seconds for " + num + " requests which is on average " + tot/num + " milliseconds per request" );
	}

}
