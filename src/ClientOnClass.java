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

public class ClientOnClass {
	public static void main(String[] args) throws ClassNotFoundException
	{
		System.out.println("You are on the client side");
		
		try{
			int port_client = 9995;
			Socket msocket = new Socket(InetAddress.getLocalHost(), port_client);
			
			ObjectInputStream ois = new ObjectInputStream(msocket.getInputStream());
			PublicKey serverPublicKey = (PublicKey) ois.readObject();
			
			DataOutputStream dos = new DataOutputStream(msocket.getOutputStream());
			
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(512);
			KeyPair clientKey = keyGen.generateKeyPair();
			
			ObjectOutputStream oos = new ObjectOutputStream(msocket.getOutputStream());
	
			System.out.println(clientKey.getPublic());
			oos.writeObject(clientKey.getPublic());
			oos.flush();
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			String plainText = "let's hang over.";
			System.out.println(String.format("Plaintext sent is : %s", plainText));
			
			byte[] cipherText = cipher.doFinal(plainText.getBytes());
			dos.writeInt(cipherText.length);
			dos.write(cipherText);
			dos.flush();
			
			MessageDigest md = MessageDigest.getInstance("MD5");
			System.out.println("The message digest algorithm used is " + md.getAlgorithm());
			System.out.println("The provider which actually implements this algorithm is " + md.getProvider());
			md.update(plainText.getBytes());
			byte[] messageDigestMD5 = md.digest();
			dos.writeInt(messageDigestMD5.length);
			dos.write(messageDigestMD5);
			dos.flush();
			
			DataInputStream dis = new DataInputStream(msocket.getInputStream());
			String result = dis.readUTF();
			System.out.println("The result returned by server is : " + result);
			String result2 = dis.readUTF();
			System.out.println("The integrity of message is checked with " + result2);
	
			dis.close();
			msocket.close();
		}catch(IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
		{
			e.getStackTrace();
		}
	}
	
	
}
