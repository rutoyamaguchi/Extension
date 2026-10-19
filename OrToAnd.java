package OrToAnd;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;

public class OrToAnd implements BurpExtension{
	@Override
	public void initialize (MontoyaApi api) {
		api.extension().setName("OrToAnd");
		api.logging().logToOutput("OrToAnd extension loaded");
		ReqHandle handler = new ReqHandle(api);
		api.http().registerHttpHandler((HttpHandler)handler);
	}
}