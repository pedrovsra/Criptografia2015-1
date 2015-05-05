public class Crypto {
	
	//private String mode;
	
	public Crypto(/*String mode*/) {
		//this.mode = mode;
	}
	
	/*public void setMode(String mode) {
		this.mode = mode;
	}*/
	
	/*public String getMode() {
		return this.mode;
	}*/
	
	public String CBC_Encrypt(String key, String message) {
		StringBuilder ss = new StringBuilder();
		//TODO
		
		return ss.toString();	
	}
	
	public String CTR_Encrypt(String key, String message) {
		StringBuilder ss = new StringBuilder();
		//TODO
		
		return ss.toString();
	}
	
	public String CBC_Decrypt(String key, String cipher) {
		StringBuilder ss = new StringBuilder();
		
		String iVector = cipher.substring(0, 32);
		String message = cipher.substring(32);
		
		//    only for testing  /////////////////
		//System.out.println("Cipher: " + message);
		//System.out.println("IV: " + iVector);
		/////////////////////////////////////////
		int charsLeft = message.length();
		String aux, auxD;
		for(int i = 0; i < message.length(); i+= 32) {
			if(i+32 > message.length()) break;
			aux = message.substring(i, i+32);
			
			auxD = strxor(key, aux);
			ss.append(strxor(iVector, auxD));
			iVector = aux;
			charsLeft -= 32;
		}
		
		if(charsLeft > 0) {
			aux = message.substring(message.length() - charsLeft);
			auxD = strxor(key, aux);
			ss.append(strxor(iVector, auxD));
		}
		
		
		//    only for testing  ////////////////////////
		//System.out.println("Message: " + ss.toString());
		////////////////////////////////////////////////
		return ss.toString();	
	}
	
	public String CTR_Decrypt(String key, String cipher) {
		StringBuilder ss = new StringBuilder();
		//TODO
		
		return ss.toString();
	}
	
	private String Enc(String key, String message) {
		return strxor(key, message);
	}
	
	private String strxor(String a, String b) {
		StringBuilder ss = new StringBuilder();
		//crops the longer message
		int size = a.length() > b.length() ? b.length() : a.length();
		
		for(int i = 0; i < size; i+=2) {
			char ca = (char) (a.charAt(i) + a.charAt(i+1));
			char cb = (char) (b.charAt(i) + b.charAt(i+1));
			
			ss.append(ca ^ cb);
		}
		
		return ss.toString();
	}
}