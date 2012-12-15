package fr.ece.android.casclient;

import java.io.InputStream;
import java.security.KeyStore;

import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;



import android.content.Context;

/**
 * A normal HTTP client class, except for the fact that it uses the specified BKS keystore to 
 * establish SSL connections with remote servers, instead of the standard Android keystore, which
 * not recognise all certification authorities, or self-signed certificates.
 * 
 * The BKS key store must be generated with an older version of Bouncing Castle compatible with 
 * Android.
 * 
 * @author Justin Templemore (adapted from the web somewhere)
 *
 */
public class ServerCertHttpClient extends DefaultHttpClient {

	private final Context activityContext;

	public ServerCertHttpClient (Context activityContext) 
	{
		// needed for embedded resource access (CAS certificate)
		this.activityContext = activityContext;
		// disable auto redirect
		this.getParams().setParameter(ClientPNames.HANDLE_REDIRECTS,false);
	}

	@Override protected ClientConnectionManager createClientConnectionManager() {
		SchemeRegistry registry = new SchemeRegistry();
		registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
		registry.register(new Scheme("https", newSslSocketFactory(), 443));
		return new SingleClientConnManager(getParams(), registry);
		//return new ThreadSafeClientConnManager(getParams(), registry);
	}

	private SSLSocketFactory newSslSocketFactory() {
		try {
			KeyStore trusted = KeyStore.getInstance("BKS");
			InputStream in = activityContext.getResources().openRawResource(R.raw.ece_cas_ssl_cert);
			try {
				trusted.load(in, "secret".toCharArray());
			} finally {
				in.close();
			}
			return new SSLSocketFactory(trusted);
		} catch (Exception e) {
			throw new AssertionError(e);
		}
	}

}
