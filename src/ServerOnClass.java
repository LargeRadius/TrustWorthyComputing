import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ServerOnClass {
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		int port_server = 9995;
		ServerSocket mss = new ServerSocket(port_server);
		int numOfConnection = 0;
		
		System.out.println("You are on the server side:");
		
		try {
			while(true) {
				System.out.println("\nServer is listening...");
				Socket ms = mss.accept();
				System.out.println(String.format("This is the %d th connection.", ++numOfConnection));
				try {
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
					keyGen.initialize(512);
					KeyPair serverKey = keyGen.generateKeyPair();
					// send server's public key to client
					ObjectOutputStream oos = new ObjectOutputStream(ms.getOutputStream());
					oos.writeObject(serverKey.getPublic());
					oos.flush();
					// get client's public key
					ObjectInputStream ois = new ObjectInputStream(ms.getInputStream());
					PublicKey clientPublicKey = (PublicKey) ois.readObject();
					System.out.println(clientPublicKey);
			
					DataInputStream dis = new DataInputStream(ms.getInputStream());
					int length = dis.readInt();
					
					byte[] cipherText = null;
					if(length>0) {
						cipherText = new byte[length];
					    dis.readFully(cipherText, 0, cipherText.length); // read the message
					}
					
					Cipher cipher = Cipher.getInstance("RSA");
					cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
					String plainText = new String(cipher.doFinal(cipherText));
					System.out.println(String.format("The plaintext decripted on server side is : %s", plainText));
					String result = String.format("The message %s is received", plainText);
					
					MessageDigest md = MessageDigest.getInstance("MD5");
					int lengthMd = dis.readInt();
					
					byte[] receivedMd = null;
					if(lengthMd>0) {
						receivedMd = new byte[lengthMd];
					    dis.readFully(receivedMd, 0, receivedMd.length); // read the message
					}
					md.update(plainText.getBytes());
					byte[] messageDigestMD5 = md.digest();
			
					DataOutputStream dos = new DataOutputStream(ms.getOutputStream());
					dos.writeUTF(result);
					if(Arrays.equals(messageDigestMD5, receivedMd)) {
						dos.writeUTF("yes");
					}else{
						dos.writeUTF("no");
					}
					
					dos.flush();
					dos.close();
					oos.close();
				} finally {
					ms.close();
				}
			}
		} finally {
			mss.close();
		}
	}	
}
